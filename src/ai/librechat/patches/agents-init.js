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
//
// Agents of active add-ons are rendered by papaia-ctl into
// /app/api/data/addon-agents/ as <addon>__<file>. They are stored with
// `papaia_managed_by: <addon>`, and an add-on agent whose file is gone is
// deleted together with its access entries and project links (tombstone),
// so removing an add-on removes its agents. Agents from the operator
// directory or the UI are never deleted.
//
// `is_collaborative` (default true) shares an agent with every user of the
// instance: LibreChat 0.8.x decides access by its ACL alone, so the script
// keeps a public VIEW entry (role `agent_viewer`) for the agent, and removes
// it when the YAML sets `is_collaborative: false`. The owner's entry is
// granted by LibreChat's own `migrate:agent-permissions` on startup.
//
// Silent if the directories are empty or missing (default behaviour for
// deployments that don't opt in via LIBRECHAT_AGENTS_DIR). Non-fatal:
// any failure here is logged and swallowed so a broken agent file does
// not prevent LibreChat itself from starting.

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { MongoClient } = require('mongodb');

const AGENTS_DIR = '/app/api/data/agents';
// Agents of active add-ons, rendered by papaia-ctl (absent without any).
const ADDON_AGENTS_DIR = '/app/api/data/addon-agents';
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

// Reads the agent YAML files of one directory. Returns null when the directory
// cannot be read for another reason than being absent, so a transient error
// never counts as "no agents" (which would tombstone every add-on agent).
function listYaml(dir) {
  try {
    return fs.readdirSync(dir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    warn(`cannot read ${dir}: ${err.message}`);
    return null;
  }
}

// Upserts one agent file. Returns the stored agent id, or null when skipped.
async function upsertAgent(agents, users, aclentries, viewerRoleId, dir, file, managedBy) {
  const raw = fs.readFileSync(path.join(dir, file), 'utf8');
  const doc = yaml.load(raw);
  if (!doc || typeof doc !== 'object') {
    warn(`${file}: not a YAML object — skip`);
    return null;
  }
  if (!doc.id || !doc.name || !doc.provider || !doc.model) {
    warn(`${file}: missing required field (id / name / provider / model) — skip`);
    return null;
  }

  const agentId = String(doc.id).startsWith('agent_') ? String(doc.id) : `agent_${doc.id}`;

  const authorId = await resolveAuthorId(users, doc);
  if (!authorId) {
    warn(`${file}: no LibreChat user available to own the agent — skip`);
    return null;
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
    // Shared with everyone in the instance by default; YAML can opt out.
    is_collaborative: doc.is_collaborative !== false,
    // Re-stamp the author on every run so a re-imported agent stays
    // owned by the right user even if the user document was rebuilt.
    author: authorId,
    updatedAt: new Date(),
  };
  // Add-on agents carry their owner, so they can be removed with the add-on.
  if (managedBy) update.papaia_managed_by = managedBy;

  await agents.updateOne(
    { id: agentId },
    {
      $set: update,
      $setOnInsert: {
        createdAt: new Date(),
        versions: [],
      },
    },
    { upsert: true },
  );
  // A document stored by an earlier run under the bare id cannot be used. The
  // old code stored the YAML value as it was, so a numeric id is a number.
  if (agentId !== doc.id) {
    const stale = await agents
      .find({ id: { $in: [doc.id, String(doc.id)] } }, { projection: { _id: 1 } })
      .toArray();
    for (const { _id } of stale) {
      await agents.deleteOne({ _id });
      await aclentries.deleteMany({ resourceType: 'agent', resourceId: _id });
    }
  }
  const stored = await agents.findOne({ id: agentId }, { projection: { _id: 1 } });
  await sharePublicly(aclentries, stored._id, update.is_collaborative, viewerRoleId, authorId);
  log(`upserted ${agentId} (${file}) author=${authorId}`);
  return agentId;
}

// Keeps or removes the public VIEW entry that makes an agent usable by every
// user of the instance. Without the `agent_viewer` role (LibreChat seeds it on
// its first start) the entry carries the permission bits only.
async function sharePublicly(aclentries, resourceId, shared, viewerRoleId, grantedBy) {
  const key = { principalType: 'public', resourceType: 'agent', resourceId };
  if (!shared) {
    await aclentries.deleteMany(key);
    return;
  }
  const entry = { permBits: 1, grantedBy, updatedAt: new Date() };
  if (viewerRoleId) entry.roleId = viewerRoleId;
  await aclentries.updateOne(
    key,
    { $set: entry, $setOnInsert: { grantedAt: new Date(), createdAt: new Date() } },
    { upsert: true },
  );
}

// Deletes the add-on agents whose file is gone (the add-on was removed or no
// longer ships it), with their access entries and project links. Agents
// created in the UI or from the operator directory carry no owner and stay.
async function removeTombstones(db, keep) {
  const agents = db.collection('agents');
  const gone = await agents
    .find({ papaia_managed_by: { $exists: true }, id: { $nin: keep } })
    .project({ _id: 1, id: 1 })
    .toArray();
  if (gone.length === 0) return;
  const objectIds = gone.map((a) => a._id);
  const ids = gone.map((a) => a.id);
  await agents.deleteMany({ _id: { $in: objectIds } });
  await db.collection('aclentries').deleteMany({
    resourceType: 'agent',
    resourceId: { $in: objectIds },
  });
  await db.collection('projects').updateMany({}, { $pull: { agentIds: { $in: ids } } });
  log(`removed ${ids.join(', ')} (add-on no longer provides them)`);
}

async function main() {
  if (!MONGO_URI) {
    warn('MONGO_URI not set — skipping');
    return;
  }

  // Connects even without any file: the agents of a removed add-on must go.
  const operatorFiles = listYaml(AGENTS_DIR);
  const addonFiles = listYaml(ADDON_AGENTS_DIR);

  const client = new MongoClient(MONGO_URI);
  try {
    await client.connect();
    const db = client.db();
    const agents = db.collection('agents');
    const users = db.collection('users');
    const aclentries = db.collection('aclentries');
    const viewerRole = await db
      .collection('accessroles')
      .findOne({ accessRoleId: 'agent_viewer' }, { projection: { _id: 1 } });
    const viewerRoleId = viewerRole ? viewerRole._id : null;

    let upserted = 0;
    let failed = 0;
    for (const file of operatorFiles || []) {
      try {
        const agentId = await upsertAgent(
          agents,
          users,
          aclentries,
          viewerRoleId,
          AGENTS_DIR,
          file,
          null,
        );
        if (agentId) upserted += 1;
        else failed += 1;
      } catch (err) {
        warn(`${file}: ${err.message}`);
        failed += 1;
      }
    }

    // Files are rendered as <addon>__<file>; the prefix names the owning add-on.
    const keep = [];
    let addonFailed = addonFiles === null;
    for (const file of addonFiles || []) {
      const managedBy = file.includes('__') ? file.split('__')[0] : null;
      try {
        const agentId = await upsertAgent(
          agents,
          users,
          aclentries,
          viewerRoleId,
          ADDON_AGENTS_DIR,
          file,
          managedBy,
        );
        if (agentId) {
          keep.push(agentId);
          upserted += 1;
        } else {
          addonFailed = true;
          failed += 1;
        }
      } catch (err) {
        warn(`${file}: ${err.message}`);
        addonFailed = true;
        failed += 1;
      }
    }
    // A file that failed may still own a stored agent: remove nothing then.
    if (addonFailed) {
      warn('an add-on agent failed — skipping the removal of stale add-on agents');
    } else {
      await removeTombstones(db, keep);
    }
    const total = (operatorFiles || []).length + (addonFiles || []).length;
    log(`done — upserted=${upserted} failed=${failed} total=${total}`);
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
