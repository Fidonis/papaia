#!/usr/bin/env node
// papAIa — remove one LibreChat user's conversation history.
//
// Run by `papaia-ctl librechat clear-history` inside the running librechat
// container: `docker exec -i -w /app <container> node - <args>`, with this file
// on stdin. It goes through LibreChat's own model methods and file strategies
// (the same ones "Delete all chats" and the file delete use), so the collection
// layout and the storage of uploaded files stay LibreChat's concern.
//
// Arguments: --email=ADDRESS [--before=YYYY-MM-DD] [--dry-run]
//
// Removes the user's conversations (with their sub-threads), messages, tool call
// records, shared links and the files that belong to the conversations. Keeps
// the account, its sign-in, its MCP connections, its agents and prompts, its
// avatar, and every file an agent uses as a resource. With --before, only the
// conversations last updated before that day (00:00 UTC) go, together with
// their messages, tool calls, shared links and files.
//
// LibreChat logs to stdout as well, so the result is the last line starting
// with RESULT_MARKER, followed by one JSON object. Exit 0 on success, 3 for an
// unknown user, 1 for every other failure.

'use strict';

require('module-alias')({ base: '/app/api' });

const mongoose = require('mongoose');
const { createModels, runAsSystem } = require('@librechat/data-schemas');
const { cleanupBulkSharedLinkPermissions } = require('@librechat/api');

const RESULT_MARKER = 'PAPAIA_RESULT ';

// Files of these contexts are not part of a conversation: the user's avatar,
// files uploaded to an agent or an assistant, and skill files.
const KEPT_CONTEXTS = ['avatar', 'agents', 'assistants', 'skill_file'];

function parseArgs(argv) {
  const args = { email: '', before: null, dryRun: false };
  for (const arg of argv) {
    if (arg.startsWith('--email=')) {
      args.email = arg.slice('--email='.length).trim().toLowerCase();
    } else if (arg.startsWith('--before=')) {
      const value = arg.slice('--before='.length);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || Number.isNaN(Date.parse(`${value}T00:00:00Z`))) {
        throw new Error(`--before must be a date as YYYY-MM-DD, not '${value}'`);
      }
      args.before = new Date(`${value}T00:00:00Z`);
    } else if (arg === '--dry-run') {
      args.dryRun = true;
    } else {
      throw new Error(`unknown argument '${arg}'`);
    }
  }
  if (!args.email) {
    throw new Error('--email is required');
  }
  return args;
}

function emit(result) {
  process.stdout.write(`${RESULT_MARKER}${JSON.stringify(result)}\n`);
}

// Every file an agent lists as a resource (file search, code, context). The
// file delete would also remove it from those agents, which must stay intact.
async function agentFileIds(Agent) {
  const ids = new Set();
  const agents = await Agent.find({ tool_resources: { $exists: true } })
    .select('tool_resources')
    .lean();
  for (const agent of agents) {
    for (const resource of Object.values(agent.tool_resources || {})) {
      for (const id of (resource && resource.file_ids) || []) {
        ids.add(id);
      }
    }
  }
  return ids;
}

// What goes: the conversations in scope and their sub-threads, and the
// filters for everything that hangs off them. Without --before that is all of
// the user's history, exactly as "Delete all chats" sees it.
async function selection(models, uid, before) {
  const { Conversation, Message, File, Agent } = models;
  const scoped = before != null;
  const roots = await Conversation.find(scoped ? { user: uid, updatedAt: { $lt: before } } : { user: uid })
    .select('conversationId')
    .lean();
  const rootIds = roots.map((c) => c.conversationId);
  let conversationIds = rootIds;
  if (scoped && rootIds.length > 0) {
    const threads = await Conversation.find({
      user: uid,
      'subagentThread.rootConversationId': { $in: rootIds },
    })
      .select('conversationId')
      .lean();
    conversationIds = [...new Set([...rootIds, ...threads.map((c) => c.conversationId)])];
  }

  const byConversation = scoped ? { user: uid, conversationId: { $in: conversationIds } } : { user: uid };

  const fileFilter = { user: uid, context: { $nin: KEPT_CONTEXTS } };
  if (scoped) {
    // A file belongs to a conversation by its own conversationId or because a
    // message of the conversation carries it.
    const messages = await Message.find(byConversation).select('files.file_id').lean();
    const attached = new Set();
    for (const message of messages) {
      for (const file of message.files || []) {
        if (file && file.file_id) attached.add(file.file_id);
      }
    }
    fileFilter.$or = [
      { conversationId: { $in: conversationIds } },
      { file_id: { $in: [...attached] } },
    ];
  }
  const kept = await agentFileIds(Agent);
  const files = (await File.find(fileFilter).lean()).filter((file) => !kept.has(file.file_id));

  return { scoped, rootFilter: scoped ? { updatedAt: { $lt: before } } : {}, conversationIds, byConversation, files };
}

async function counts(models, sel) {
  const { Conversation, Message, SharedLink, ToolCall } = models;
  const [conversations, messages, sharedLinks, toolCalls] = await Promise.all([
    sel.scoped
      ? Promise.resolve(sel.conversationIds.length)
      : Conversation.countDocuments(sel.byConversation),
    Message.countDocuments(sel.byConversation),
    SharedLink.countDocuments(sel.byConversation),
    ToolCall.countDocuments(sel.byConversation),
  ]);
  return {
    conversations,
    messages,
    files: sel.files.length,
    shared_links: sharedLinks,
    tool_calls: toolCalls,
  };
}

async function deleteFiles(user, files) {
  if (files.length === 0) {
    return { deleted: 0, failed: [] };
  }
  // Loaded only when needed: the file services pull in most of the server.
  const { getAppConfig } = require('~/server/services/Config');
  const { processDeleteRequest } = require('~/server/services/Files/process');
  const appConfig = await getAppConfig({ baseOnly: true });
  const req = {
    user: { id: user._id.toString(), tenantId: user.tenantId },
    config: appConfig,
    body: {},
  };
  const result = await processDeleteRequest({ req, files });
  return { deleted: result.deletedFileIds.length, failed: result.failedFileIds };
}

async function clear(models, user, sel) {
  const db = require('~/models');
  const uid = user._id.toString();
  const { SharedLink } = models;

  const convos = await db.deleteConvos(uid, sel.rootFilter, { allowEmpty: true });
  let messages = (convos.messages && convos.messages.deletedCount) || 0;
  // "Delete all chats" also removes messages left without a conversation.
  const rest = await db.deleteMessages(sel.byConversation);
  messages += rest.deletedCount || 0;

  const toolCalls = await models.ToolCall.deleteMany(sel.byConversation);

  // As LibreChat's deleteAllSharedLinksWithCleanup, but waiting for the ACL
  // cleanup, which LibreChat runs in the background of a request.
  const links = (await SharedLink.find(sel.byConversation).select('_id').lean()).map((l) => l._id);
  const linkResult = await SharedLink.deleteMany(sel.byConversation);
  if (links.length > 0) {
    await cleanupBulkSharedLinkPermissions(links);
  }

  const files = await deleteFiles(user, sel.files);

  return {
    conversations: convos.deletedCount || 0,
    messages,
    files: files.deleted,
    shared_links: linkResult.deletedCount || 0,
    tool_calls: toolCalls.deletedCount || 0,
    files_failed: files.failed,
  };
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    emit({ error: 'usage', message: error.message });
    return 1;
  }

  const { connectDb } = require('~/db/connect');
  await connectDb();
  const models = createModels(mongoose);

  return runAsSystem(async () => {
    const user = await models.User.findOne({ email: args.email }).select('_id email tenantId').lean();
    if (!user) {
      emit({ error: 'unknown_user', email: args.email });
      return 3;
    }
    const uid = user._id.toString();
    const sel = await selection(models, uid, args.before);
    if (args.dryRun) {
      emit({ email: user.email, dry_run: true, ...(await counts(models, sel)) });
      return 0;
    }
    const result = await clear(models, user, sel);
    emit({ email: user.email, dry_run: false, ...result });
    return result.files_failed.length > 0 ? 1 : 0;
  });
}

main()
  .catch((error) => {
    emit({ error: 'failed', message: error && error.message ? error.message : String(error) });
    return 1;
  })
  .then(async (code) => {
    try {
      await mongoose.disconnect();
    } catch {
      // The result is out; a failed disconnect changes nothing.
    }
    // Caches and queues of the server modules keep handles open.
    process.exit(code);
  });
