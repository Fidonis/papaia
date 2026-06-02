#!/usr/bin/env node
// papAIa startup patch — provision LibreChat agents from a host directory.
//
// Reads every *.yaml / *.yml file from /app/api/data/agents/ and upserts a
// corresponding agent document in the MongoDB `agents` collection. The
// upsert is keyed by the YAML `id` field so re-running on every container
// start is idempotent.
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

        const authorId = await resolveAuthorId(users, doc);
        if (!authorId) {
          warn(`${file}: no LibreChat user available to own the agent — skip`);
          failed += 1;
          continue;
        }

        const update = {
          id: doc.id,
          name: doc.name,
          description: doc.description ?? '',
          provider: doc.provider,
          model: doc.model,
          instructions: doc.instructions ?? '',
          mcpServers: Array.isArray(doc.mcpServers) ? doc.mcpServers : [],
          model_parameters: doc.model_parameters ?? {},
          tools: Array.isArray(doc.tools) ? doc.tools : [],
          // Shared with everyone in the instance by default; YAML can opt out.
          is_collaborative: doc.is_collaborative !== false,
          // Re-stamp the author on every run so a re-imported agent stays
          // owned by the right user even if the user document was rebuilt.
          author: authorId,
          updatedAt: new Date(),
        };

        await agents.updateOne(
          { id: doc.id },
          {
            $set: update,
            $setOnInsert: {
              createdAt: new Date(),
              versions: [],
            },
          },
          { upsert: true },
        );
        upserted += 1;
        log(`upserted ${doc.id} (${file}) author=${authorId}`);
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
