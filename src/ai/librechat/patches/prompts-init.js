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
// Silent if the directory is empty or missing. Non-fatal on per-file
// errors: a single broken prompt cannot block LibreChat from starting.

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { MongoClient, ObjectId } = require('mongodb');

const PROMPTS_DIR = '/app/api/data/prompts';
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

async function main() {
  if (!MONGO_URI) {
    warn('MONGO_URI not set — skipping');
    return;
  }

  let entries;
  try {
    entries = fs.readdirSync(PROMPTS_DIR);
  } catch (err) {
    if (err.code === 'ENOENT') {
      log(`directory ${PROMPTS_DIR} missing — skipping`);
      return;
    }
    warn(`cannot read ${PROMPTS_DIR}: ${err.message}`);
    return;
  }

  const files = entries.filter((f) => /\.(md|markdown)$/i.test(f));
  if (files.length === 0) {
    log(`no prompt files in ${PROMPTS_DIR} — nothing to do`);
    return;
  }

  const client = new MongoClient(MONGO_URI);
  try {
    await client.connect();
    const db = client.db();
    const users = db.collection('users');
    const projects = db.collection('projects');
    const promptgroups = db.collection('promptgroups');
    const prompts = db.collection('prompts');

    let upserted = 0;
    let failed = 0;
    for (const file of files) {
      const full = path.join(PROMPTS_DIR, file);
      try {
        const raw = fs.readFileSync(full, 'utf8');
        const { meta, body } = parseFrontMatter(raw);
        if (!meta) {
          warn(`${file}: missing YAML front matter — skip`);
          failed += 1;
          continue;
        }
        const required = ['name', 'category', 'command', 'oneliner'];
        const missing = required.filter((k) => !meta[k]);
        if (missing.length > 0) {
          warn(`${file}: missing required keys [${missing.join(', ')}] — skip`);
          failed += 1;
          continue;
        }
        const promptText = body.trim();
        if (!promptText) {
          warn(`${file}: empty prompt body — skip`);
          failed += 1;
          continue;
        }

        const authorId = await resolveAuthorId(users, meta);
        if (!authorId) {
          warn(`${file}: no LibreChat user available — skip`);
          failed += 1;
          continue;
        }
        const projectId = await ensureGlobalProject(projects, authorId);

        // Upsert the prompt group keyed by (name, author).
        let group = await promptgroups.findOne({ name: meta.name, author: authorId });
        if (group) {
          await promptgroups.updateOne(
            { _id: group._id },
            {
              $set: {
                oneliner: meta.oneliner,
                category: meta.category,
                command: meta.command,
                projectIds: [projectId],
                updatedAt: new Date(),
              },
            },
          );
        } else {
          const ins = await promptgroups.insertOne({
            name: meta.name,
            oneliner: meta.oneliner,
            category: meta.category,
            command: meta.command,
            projectIds: [projectId],
            numberOfGenerations: 0,
            author: authorId,
            authorName: meta.author_name || 'system',
            createdAt: new Date(),
            updatedAt: new Date(),
          });
          group = { _id: ins.insertedId };
        }

        // Upsert one prompt under the group with the latest body.
        let prompt = await prompts.findOne({ groupId: group._id, author: authorId });
        if (prompt) {
          await prompts.updateOne(
            { _id: prompt._id },
            { $set: { prompt: promptText, type: 'text', updatedAt: new Date() } },
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
        await projects.updateOne(
          { _id: projectId },
          { $addToSet: { promptGroupIds: group._id } },
        );

        upserted += 1;
        log(`upserted ${meta.command || meta.name} (${file})`);
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
    process.exit(0);
  });
