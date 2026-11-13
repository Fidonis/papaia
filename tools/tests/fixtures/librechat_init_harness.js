// Runs one of LibreChat's init scripts (agents-init.js, prompts-init.js) against an
// in-memory stand-in for MongoDB, for test_librechat_init_scripts.py.
//
//   node librechat_init_harness.js <script> <data-root> <state.json>
//
// <data-root> replaces /app/api/data, so the script reads the test's agent and prompt
// files. The database starts from <state.json> (collection name -> documents) and is
// written back there when the script exits. js-yaml is replaced by JSON.parse, so the
// test files are written as JSON, which is YAML too.

'use strict';

const fs = require('fs');
const Module = require('module');

const [script, dataRoot, statePath] = process.argv.slice(2);
const APP_DATA = '/app/api/data';
const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
let nextId = 1;
for (const docs of Object.values(state)) {
  for (const doc of docs) {
    const n = Number(String(doc._id).replace(/^oid/, ''));
    if (n >= nextId) nextId = n + 1;
  }
}

const mapPath = (p) => (typeof p === 'string' && p.startsWith(APP_DATA) ? dataRoot + p.slice(APP_DATA.length) : p);
const { readdirSync, readFileSync } = fs;
fs.readdirSync = (p, ...rest) => readdirSync(mapPath(p), ...rest);
fs.readFileSync = (p, ...rest) => readFileSync(mapPath(p), ...rest);

const same = (a, b) => (a !== null && typeof a === 'object' ? JSON.stringify(a) === JSON.stringify(b) : a === b);

function matches(doc, query) {
  return Object.entries(query).every(([key, cond]) => {
    const value = doc[key];
    if (cond !== null && typeof cond === 'object' && Object.keys(cond).some((k) => k.startsWith('$'))) {
      if ('$in' in cond && !cond.$in.some((v) => same(value, v))) return false;
      if ('$nin' in cond && cond.$nin.some((v) => same(value, v))) return false;
      if ('$exists' in cond && (value !== undefined) !== cond.$exists) return false;
      return true;
    }
    return same(value, cond);
  });
}

// MongoDB rejects an update that names one path in two operators (`$set` and `$unset`
// of the same field, say) and fails the whole update; the stand-in does the same, so
// such an update cannot pass the tests.
function checkConflicts(change) {
  const paths = Object.entries(change).flatMap(([op, fields]) => Object.keys(fields || {}).map((p) => [op, p]));
  for (const [op, p] of paths) {
    for (const [otherOp, other] of paths) {
      if (op !== otherOp && (p === other || p.startsWith(`${other}.`))) {
        throw new Error(`Updating the path '${p}' would create a conflict at '${other}'`);
      }
    }
  }
}

function apply(doc, change) {
  Object.assign(doc, change.$set || {});
  for (const key of Object.keys(change.$unset || {})) delete doc[key];
  for (const [key, value] of Object.entries(change.$addToSet || {})) {
    doc[key] = doc[key] || [];
    if (!doc[key].some((v) => same(v, value))) doc[key].push(value);
  }
  for (const [key, cond] of Object.entries(change.$pull || {})) {
    if (Array.isArray(doc[key])) doc[key] = doc[key].filter((v) => !cond.$in.some((x) => same(v, x)));
  }
}

function project(doc, projection) {
  if (!projection) return { ...doc };
  const out = {};
  for (const key of Object.keys(projection)) if (key in doc) out[key] = doc[key];
  return out;
}

class Collection {
  constructor(docs) {
    this.docs = docs;
  }
  async findOne(query = {}, opts = {}) {
    const doc = this.docs.find((d) => matches(d, query));
    return doc ? project(doc, opts.projection) : null;
  }
  find(query = {}, opts = {}) {
    let projection = opts.projection;
    const cursor = {
      project: (p) => {
        projection = p;
        return cursor;
      },
      toArray: async () => this.docs.filter((d) => matches(d, query)).map((d) => project(d, projection)),
    };
    return cursor;
  }
  async insertOne(doc) {
    const stored = { _id: `oid${nextId++}`, ...doc };
    this.docs.push(stored);
    return { insertedId: stored._id };
  }
  // Applies `change` to the first match, or to a new document on upsert. Returns the
  // document before and after the change (null where there is none).
  modify(query, change, opts) {
    checkConflicts(change);
    let doc = this.docs.find((d) => matches(d, query));
    const before = doc ? JSON.parse(JSON.stringify(doc)) : null;
    if (!doc) {
      if (!opts.upsert) return { before, after: null };
      doc = { _id: `oid${nextId++}` };
      for (const [key, cond] of Object.entries(query)) {
        if (cond === null || typeof cond !== 'object') doc[key] = cond;
      }
      Object.assign(doc, change.$setOnInsert || {});
      this.docs.push(doc);
    }
    apply(doc, change);
    return { before, after: doc };
  }
  async updateOne(query, change, opts = {}) {
    this.modify(query, change, opts);
  }
  // Returns the document itself, as the driver (6.x) does: before the change unless
  // `returnDocument: 'after'`.
  async findOneAndUpdate(query, change, opts = {}) {
    const { before, after } = this.modify(query, change, opts);
    const doc = opts.returnDocument === 'after' ? after : before;
    return doc ? project(doc, opts.projection) : null;
  }
  async updateMany(query, change) {
    checkConflicts(change);
    for (const doc of this.docs.filter((d) => matches(d, query))) apply(doc, change);
  }
  async deleteOne(query) {
    const i = this.docs.findIndex((d) => matches(d, query));
    if (i >= 0) this.docs.splice(i, 1);
  }
  async findOneAndDelete(query) {
    const i = this.docs.findIndex((d) => matches(d, query));
    return i >= 0 ? this.docs.splice(i, 1)[0] : null;
  }
  async deleteMany(query) {
    for (let i = this.docs.length - 1; i >= 0; i -= 1) if (matches(this.docs[i], query)) this.docs.splice(i, 1);
  }
}

const db = {
  collection(name) {
    state[name] = state[name] || [];
    return new Collection(state[name]);
  },
};

class MongoClient {
  async connect() {}
  db() {
    return db;
  }
  async close() {}
}

const stubs = {
  mongodb: { MongoClient, ObjectId: String },
  'js-yaml': { load: (text) => JSON.parse(text) },
};
const load = Module._load;
Module._load = function stubbed(request, ...rest) {
  return request in stubs ? stubs[request] : load.call(this, request, ...rest);
};

const exit = process.exit;
process.exit = (code) => {
  fs.writeFileSync(statePath, JSON.stringify(state, null, 2));
  exit(code);
};
process.env.MONGO_URI = 'mongodb://stand-in';
require(script);
