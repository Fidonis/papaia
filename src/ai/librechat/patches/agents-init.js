#!/usr/bin/env node
// papAIa startup patch — provision LibreChat agents from a host directory.
//
// Reads every *.yaml / *.yml file from /app/api/data/agents/ and upserts a
// corresponding agent document in the MongoDB `agents` collection. The
// upsert is keyed by the YAML `id` field so re-running on every container
// start is idempotent.
//
// LibreChat treats every agent id without the `agent_` prefix as an ephemeral
// agent and never loads the stored document, so the prefix is added when the
// YAML omits it (`id: paperless-assistant` is stored as `agent_paperless-assistant`).
// A document an earlier version stored under the bare id is removed, together with
// the ACL entries LibreChat granted on it.
//
// Every user may view and use a provisioned agent unless the YAML sets
// `is_collaborative: false`. LibreChat decides that by an ACL entry for the public
// principal; `migrate:agent-permissions` only grants one to agents of the legacy
// `instance` project, and only once, so this script writes (or removes) it on every
// run. The owner's entry stays with the migration, which runs after this script.
//
// Silent if the directory is empty or missing (default behaviour for
// deployments that don't opt in via LIBRECHAT_AGENTS_DIR). Non-fatal:
// any failure here is logged and swallowed so a broken agent file does
// not prevent LibreChat itself from starting.

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { MongoClient } = require('mongodb');

const AGENTS_DIR = '/app/api/data/agents';
const MONGO_URI = process.env.MONGO_URI;

// LibreChat's access role for "can view and use" an agent, and its permission bits.
const VIEWER_ROLE = 'agent_viewer';
const VIEW_BITS = 1;

const log = (msg) => console.log(`[agents-init] ${msg}`);
const warn = (msg) => console.warn(`[agents-init] ${msg}`);

// Resolves the MongoDB user ObjectId an agent should be filed under.
// Tries the explicit author_email from the YAML first, falls back to the
// first user with role ADMIN, then to any user. Returns null if the
// instance has no users yet — in which case the agent is skipped.
async function resolveAuthorId(users, doc) {
  if (doc.author_email) {
    const match = await users.findOne({ email: doc.author_email });
    if (match) return match._id;
    warn(`${doc.id}: author_email '${doc.author_email}' has no matching user — falling back`);
  }
  const admin = await users.findOne({ role: 'ADMIN' });
  if (admin) return admin._id;
  const anyUser = await users.findOne();
  return anyUser ? anyUser._id : null;
}

// Grants every user view access to the agent document `agentDoc`, or takes it away
// when `shared` is false. The role reference is added once LibreChat has seeded its
// access roles (the first start runs this script before the server does).
async function setPublicAccess(db, agentDoc, shared) {
  const acl = db.collection('aclentries');
  const query = { principalType: 'public', resourceType: 'agent', resourceId: agentDoc._id };
  if (!shared) {
    await acl.deleteMany(query);
    return;
  }
  const role = await db.collection('accessroles').findOne({ accessRoleId: VIEWER_ROLE });
  await acl.updateOne(
    query,
    {
      $set: {
        permBits: role ? role.permBits : VIEW_BITS,
        grantedBy: agentDoc.author,
        grantedAt: new Date(),
        ...(role ? { roleId: role._id } : {}),
      },
    },
    { upsert: true },
  );
}

async function main() {
  if (!MONGO_URI) {
    warn('MONGO_URI not set — skipping');
    return;
  }

  let entries;
  try {
    entries = fs.readdirSync(AGENTS_DIR);
  } catch (err) {
    if (err.code === 'ENOENT') {
      log(`directory ${AGENTS_DIR} missing — skipping`);
      return;
    }
    warn(`cannot read ${AGENTS_DIR}: ${err.message}`);
    return;
  }

  const files = entries.filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  if (files.length === 0) {
    log(`no agent YAML in ${AGENTS_DIR} — nothing to do`);
    return;
  }

  const client = new MongoClient(MONGO_URI);
  try {
    await client.connect();
    const db = client.db();
    const agents = db.collection('agents');
    const users = db.collection('users');

    let upserted = 0;
    let failed = 0;
    for (const file of files) {
      const full = path.join(AGENTS_DIR, file);
      try {
        const raw = fs.readFileSync(full, 'utf8');
        const doc = yaml.load(raw);
        if (!doc || typeof doc !== 'object') {
          warn(`${file}: not a YAML object — skip`);
          failed += 1;
          continue;
        }
        if (!doc.id || !doc.name || !doc.provider || !doc.model) {
          warn(`${file}: missing required field (id / name / provider / model) — skip`);
          failed += 1;
          continue;
        }

        const agentId = String(doc.id).startsWith('agent_') ? String(doc.id) : `agent_${doc.id}`;

        const authorId = await resolveAuthorId(users, doc);
        if (!authorId) {
          warn(`${file}: no LibreChat user available to own the agent — skip`);
          failed += 1;
          continue;
        }

        const update = {
          id: agentId,
          name: doc.name,
          description: doc.description ?? '',
          provider: doc.provider,
          model: doc.model,
          instructions: doc.instructions ?? '',
          mcpServers: Array.isArray(doc.mcpServers) ? doc.mcpServers : [],
          model_parameters: doc.model_parameters ?? {},
          tools: Array.isArray(doc.tools) ? doc.tools : [],
          // Re-stamp the author on every run so a re-imported agent stays
          // owned by the right user even if the user document was rebuilt.
          author: authorId,
          updatedAt: new Date(),
        };

        const stored = await agents.findOneAndUpdate(
          { id: agentId },
          {
            $set: update,
            // Written by earlier versions; LibreChat's schema has no such field.
            $unset: { is_collaborative: '' },
            $setOnInsert: {
              createdAt: new Date(),
              versions: [],
            },
          },
          { upsert: true, returnDocument: 'after' },
        );
        // A document stored by an earlier run under the bare id cannot be used. The id
        // is matched as the YAML has it, so a numeric one is found too.
        if (agentId !== doc.id) {
          const stale = await agents.findOneAndDelete({ id: doc.id });
          if (stale) {
            await db
              .collection('aclentries')
              .deleteMany({ resourceType: 'agent', resourceId: stale._id });
            log(`removed ${doc.id}, stored without the agent_ prefix`);
          }
        }
        await setPublicAccess(db, stored, doc.is_collaborative !== false);
        upserted += 1;
        log(`upserted ${agentId} (${file}) author=${authorId}`);
      } catch (err) {
        warn(`${file}: ${err.message}`);
        failed += 1;
      }
    }
    log(`done — upserted=${upserted} failed=${failed} total=${files.length}`);
  } catch (err) {
    warn(`mongo error: ${err.message}`);
  } finally {
    await client.close().catch(() => {});
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    warn(`fatal: ${err.message}`);
    // Don't block LibreChat from starting — agents are optional.
    process.exit(0);
  });
