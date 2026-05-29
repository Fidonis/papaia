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
          updatedAt: new Date(),
        };

        await agents.updateOne(
          { id: doc.id },
          {
            $set: update,
            $setOnInsert: {
              createdAt: new Date(),
              author: 'system',
            },
          },
          { upsert: true },
        );
        upserted += 1;
        log(`upserted ${doc.id} (${file})`);
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
