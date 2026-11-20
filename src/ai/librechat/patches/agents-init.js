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
// Agents of active add-ons are rendered by papaia-ctl into
// /app/api/data/addon-agents/ as <addon>__<file>. They are stored with
// `papaia_managed_by: <addon>`, and an add-on agent whose file is gone is
// deleted together with its access entries and project links (tombstone),
// so removing an add-on removes its agents. Agents from the operator
// directory or the UI are never deleted. An operator file with the id of an
// add-on agent wins: the add-on file is skipped with a warning and the stored
// agent loses its add-on mark, so it survives the removal of the add-on.
// While an operator file fails, its id is unknown: add-on files then leave
// every stored agent without the add-on mark alone, and nothing is removed.
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

// Returned for an add-on file whose id an operator file already provides.
const TAKEN = Symbol('taken');

// Upserts one agent file. Returns the stored agent id, null when the file is
// skipped, or TAKEN when an add-on file collides with an operator agent.
// `guarded` is set while an operator file failed: an add-on file then does not
// take over a stored agent that has no add-on mark, since that agent may be the
// failed file's.
async function upsertAgent(db, dir, file, managedBy, taken, guarded) {
  const agents = db.collection('agents');
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
  if (managedBy && taken.has(agentId)) {
    warn(`${file}: ${agentId} is provided by the operator directory — the add-on file is skipped`);
    return TAKEN;
  }
  if (managedBy && guarded) {
    const existing = await agents.findOne({ id: agentId }, { projection: { papaia_managed_by: 1 } });
    if (existing && existing.papaia_managed_by === undefined) {
      warn(`${file}: ${agentId} is stored without an add-on mark and an operator file failed — the add-on file is skipped`);
      return TAKEN;
    }
  }

  const authorId = await resolveAuthorId(db.collection('users'), doc);
  if (!authorId) {
    warn(`${file}: no LibreChat user available to own the agent — skip`);
    return null;
  }

  // LibreChat equips a stored agent from `tools` alone; `mcpServers` adds no
  // tools by itself. An empty list next to MCP servers therefore means every
  // tool of those servers, so the per-server wildcard key is derived. A
  // non-empty list is stored as written: single keys (<tool>_mcp_<server>)
  // keep the tool prompt small, which small local models need.
  const mcpServers = Array.isArray(doc.mcpServers) ? doc.mcpServers : [];
  let tools = Array.isArray(doc.tools) ? doc.tools : [];
  if (tools.length === 0 && mcpServers.length > 0) {
    tools = mcpServers.map((server) => `sys__all__sys_mcp_${server}`);
  }

  const update = {
    id: agentId,
    name: doc.name,
    description: doc.description ?? '',
    provider: doc.provider,
    model: doc.model,
    instructions: doc.instructions ?? '',
    mcpServers,
    model_parameters: doc.model_parameters ?? {},
    tools,
    // Re-stamp the author on every run so a re-imported agent stays
    // owned by the right user even if the user document was rebuilt.
    author: authorId,
    updatedAt: new Date(),
  };
  // Written by earlier versions; LibreChat's schema has no such field. A path may
  // appear in only one update operator, so `update` must not set it.
  const unset = { is_collaborative: '' };
  // Add-on agents carry their owner, so they can be removed with the add-on.
  // An operator file drops the mark: the agent is no longer the add-on's.
  if (managedBy) update.papaia_managed_by = managedBy;
  else unset.papaia_managed_by = '';

  const stored = await agents.findOneAndUpdate(
    { id: agentId },
    {
      $set: update,
      $unset: unset,
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
      // Every entry on the document, whatever its resource type.
      await db.collection('aclentries').deleteMany({ resourceId: stale._id });
      log(`removed ${doc.id}, stored without the agent_ prefix`);
    }
  }
  await setPublicAccess(db, stored, doc.is_collaborative !== false);
  log(`upserted ${agentId} (${file}) author=${authorId}`);
  return agentId;
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
  await db.collection('aclentries').deleteMany({ resourceId: { $in: objectIds } });
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

    let upserted = 0;
    let failed = 0;
    // A failed operator file may provide the id of a stored agent: see `guarded`.
    let operatorFailed = operatorFiles === null;
    // Ids the operator directory provides; an add-on file cannot take them over.
    const taken = new Set();
    for (const file of operatorFiles || []) {
      try {
        const agentId = await upsertAgent(db, AGENTS_DIR, file, null, taken);
        if (agentId) {
          taken.add(agentId);
          upserted += 1;
        } else {
          operatorFailed = true;
          failed += 1;
        }
      } catch (err) {
        warn(`${file}: ${err.message}`);
        operatorFailed = true;
        failed += 1;
      }
    }

    // Files are rendered as <addon>__<file>; the prefix names the owning add-on.
    const keep = [];
    let addonFailed = addonFiles === null;
    for (const file of addonFiles || []) {
      const managedBy = file.includes('__') ? file.split('__')[0] : null;
      try {
        const agentId = await upsertAgent(db, ADDON_AGENTS_DIR, file, managedBy, taken, operatorFailed);
        if (agentId === TAKEN) continue;
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
    if (addonFailed || operatorFailed) {
      warn('an agent file failed — skipping the removal of stale add-on agents');
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
