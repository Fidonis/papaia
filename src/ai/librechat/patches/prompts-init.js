#!/usr/bin/env node
// papAIa startup patch — provision LibreChat prompts from a host directory.
//
// Reads every *.md / *.markdown file from /app/api/data/prompts/, parses
// a leading YAML front matter (--- … ---) for metadata, treats the
// remainder as the prompt body, and upserts a prompt group + production
// prompt in the corresponding MongoDB collections.
//
// Required front-matter keys: name, category, command, oneliner.
// Optional: author_email, description, projectIds (defaults to the
// global "instance" project so every user sees the prompt).
//
// Prompts of active add-ons are rendered by papaia-ctl into
// /app/api/data/addon-prompts/ as <addon>__<file>, stored with
// `papaia_managed_by: <addon>` and keyed by (add-on, command); an add-on prompt
// whose file is gone is deleted (tombstone). Operator and UI prompts stay.
//
// Silent if the directories are empty or missing. Non-fatal on per-file
// errors: a single broken prompt cannot block LibreChat from starting.

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { MongoClient, ObjectId } = require('mongodb');

const PROMPTS_DIR = '/app/api/data/prompts';
// Prompts of active add-ons, rendered by papaia-ctl (absent without any).
const ADDON_PROMPTS_DIR = '/app/api/data/addon-prompts';
const MONGO_URI = process.env.MONGO_URI;

const log = (msg) => console.log(`[prompts-init] ${msg}`);
const warn = (msg) => console.warn(`[prompts-init] ${msg}`);

function parseFrontMatter(raw) {
  // Matches a top-of-file YAML block delimited by --- … ---.
  const match = raw.match(/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/);
  if (!match) return { meta: null, body: raw };
  let meta;
  try {
    meta = yaml.load(match[1]);
  } catch (err) {
    throw new Error(`bad YAML front matter: ${err.message}`);
  }
  return { meta: meta || {}, body: match[2] };
}

async function resolveAuthorId(users, doc) {
  if (doc.author_email) {
    const m = await users.findOne({ email: doc.author_email });
    if (m) return m._id;
    warn(`author_email '${doc.author_email}' not found — falling back`);
  }
  const admin = await users.findOne({ role: 'ADMIN' });
  if (admin) return admin._id;
  const any = await users.findOne();
  return any ? any._id : null;
}

async function ensureGlobalProject(projects, authorId) {
  const existing = await projects.findOne({ name: 'instance' });
  if (existing) return existing._id;
  const ins = await projects.insertOne({
    name: 'instance',
    authorId,
    promptGroupIds: [],
    agentIds: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  return ins.insertedId;
}

// Lists the prompt files of one directory; null when it cannot be read for another
// reason than being absent, so a transient error never tombstones add-on prompts.
function listPrompts(dir) {
  try {
    return fs.readdirSync(dir).filter((f) => /\.(md|markdown)$/i.test(f));
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    warn(`cannot read ${dir}: ${err.message}`);
    return null;
  }
}

// Upserts one prompt file. Returns the prompt group id, or null when skipped.
// Operator prompts are keyed by (name, author) among the groups without an add-on
// mark, so an add-on group of the same name is never taken over; add-on prompts by
// (owning add-on, command), which stays stable when the author falls back to another user.
async function upsertPrompt(db, dir, file, managedBy) {
  const users = db.collection('users');
  const projects = db.collection('projects');
  const promptgroups = db.collection('promptgroups');
  const prompts = db.collection('prompts');

  const raw = fs.readFileSync(path.join(dir, file), 'utf8');
  const { meta, body } = parseFrontMatter(raw);
  if (!meta) {
    warn(`${file}: missing YAML front matter — skip`);
    return null;
  }
  const required = ['name', 'category', 'command', 'oneliner'];
  const missing = required.filter((k) => !meta[k]);
  if (missing.length > 0) {
    warn(`${file}: missing required keys [${missing.join(', ')}] — skip`);
    return null;
  }
  const promptText = body.trim();
  if (!promptText) {
    warn(`${file}: empty prompt body — skip`);
    return null;
  }

  const authorId = await resolveAuthorId(users, meta);
  if (!authorId) {
    warn(`${file}: no LibreChat user available — skip`);
    return null;
  }
  const projectId = await ensureGlobalProject(projects, authorId);

  const key = managedBy
    ? { papaia_managed_by: managedBy, command: meta.command }
    : { name: meta.name, author: authorId, papaia_managed_by: { $exists: false } };
  let group = await promptgroups.findOne(key);
  const fields = {
    name: meta.name,
    oneliner: meta.oneliner,
    category: meta.category,
    command: meta.command,
    projectIds: [projectId],
    updatedAt: new Date(),
  };
  if (managedBy) {
    fields.papaia_managed_by = managedBy;
    fields.author = authorId;
  }
  if (group) {
    await promptgroups.updateOne({ _id: group._id }, { $set: fields });
  } else {
    const ins = await promptgroups.insertOne({
      ...fields,
      numberOfGenerations: 0,
      author: authorId,
      authorName: meta.author_name || 'system',
      createdAt: new Date(),
    });
    group = { _id: ins.insertedId };
  }

  // Upsert one prompt under the group with the latest body.
  let prompt = await prompts.findOne({ groupId: group._id });
  if (prompt) {
    await prompts.updateOne(
      { _id: prompt._id },
      { $set: { prompt: promptText, type: 'text', author: authorId, updatedAt: new Date() } },
    );
  } else {
    const ins = await prompts.insertOne({
      groupId: group._id,
      author: authorId,
      prompt: promptText,
      type: 'text',
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    prompt = { _id: ins.insertedId };
  }

  // Stamp productionId and link into the global project.
  await promptgroups.updateOne(
    { _id: group._id },
    { $set: { productionId: prompt._id, updatedAt: new Date() } },
  );
  await projects.updateOne({ _id: projectId }, { $addToSet: { promptGroupIds: group._id } });

  log(`upserted ${meta.command || meta.name} (${file})`);
  return group._id;
}

// Deletes the add-on prompt groups whose file is gone, with their prompts, access
// entries and project links. Prompts from the operator directory or the UI carry no
// owner and stay.
async function removeTombstones(db, keep) {
  const promptgroups = db.collection('promptgroups');
  const gone = await promptgroups
    .find({ papaia_managed_by: { $exists: true }, _id: { $nin: keep } })
    .project({ _id: 1, command: 1 })
    .toArray();
  if (gone.length === 0) return;
  const ids = gone.map((g) => g._id);
  await promptgroups.deleteMany({ _id: { $in: ids } });
  await db.collection('prompts').deleteMany({ groupId: { $in: ids } });
  await db.collection('aclentries').deleteMany({
    resourceType: 'promptGroup',
    resourceId: { $in: ids },
  });
  await db.collection('projects').updateMany({}, { $pull: { promptGroupIds: { $in: ids } } });
  log(`removed /${gone.map((g) => g.command).join(', /')} (add-on no longer provides them)`);
}

async function main() {
  if (!MONGO_URI) {
    warn('MONGO_URI not set — skipping');
    return;
  }

  // Connects even without any file: the prompts of a removed add-on must go.
  const operatorFiles = listPrompts(PROMPTS_DIR);
  const addonFiles = listPrompts(ADDON_PROMPTS_DIR);

  const client = new MongoClient(MONGO_URI);
  try {
    await client.connect();
    const db = client.db();

    let upserted = 0;
    let failed = 0;
    for (const file of operatorFiles || []) {
      try {
        if (await upsertPrompt(db, PROMPTS_DIR, file, null)) upserted += 1;
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
        const groupId = await upsertPrompt(db, ADDON_PROMPTS_DIR, file, managedBy);
        if (groupId) {
          keep.push(groupId);
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
    // A file that failed may still own a stored prompt: remove nothing then.
    if (addonFailed) {
      warn('an add-on prompt failed — skipping the removal of stale add-on prompts');
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
    process.exit(0);
  });
