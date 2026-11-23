import { DEFAULT_MAP_LIMIT, buildMemoryMap, recallFileTreeOn, memoryPathTree, findMemories } from '../../memorymap/memoryMap.js';
import * as z from 'zod';
import { refusal } from '../../toolRefusal.js';
import { factQueryTerms } from '../agentMemory.js';
import { normalizeScope } from '../scope.js';
import { DEFAULT_LOOKUP_LIMIT, MAX_LOOKUP_LIMIT, markStoredMemory, toolError } from './shared.js';
import type { ToolContext } from './setup.js';
import { chatNamer } from '../../memorymap/topics.js';
import { resolveEvidenceChat } from '../../evidence/options.js';
import { resolveEvidenceMode } from '../../evidence/gate.js';
import { TOPIC_NAMING_LOCATION, TOPIC_NAMING_MODEL, vertexNamingChat } from '../../memorymap/vertexNaming.js';
import { VertexEmbeddingProvider } from '../../embeddings/vertex.js';

/** One Vertex key's token exchange, kept for the process: topics are named rarely, and each naming reuses it. */
let namingKey: { id: string; provider: VertexEmbeddingProvider } | null = null;

function vertexTokenFor(keyFile: string, project: string): (signal?: AbortSignal) => Promise<string> {
  const id = `${keyFile}\0${project}`;
  if (namingKey?.id !== id) namingKey = { id, provider: new VertexEmbeddingProvider({ keyFile, project, location: TOPIC_NAMING_LOCATION }) };
  const provider = namingKey.provider;
  return (signal) => provider.bearerToken(signal);
}

/**
 * The dashboard's topic grouping: vectors from the engine's index, and names from a model only where the memories'
 * text already goes to one. A workspace that embeds with Vertex has its topics named by Gemini on the same project
 * and key (vertexNaming.ts); otherwise the evidence pass's model names them where that pass would already send notes
 * (its mode is not off and it has a key); otherwise the names are keywords.
 */
function topicOptions(ctx: ToolContext) {
  const index = ctx.engine.vectorIndex;
  const { config } = ctx;
  let names;
  try {
    if (config.embeddingProvider === 'vertex' && config.vertexKeyFile && config.vertexProject) {
      const chat = vertexNamingChat({ project: config.vertexProject, token: vertexTokenFor(config.vertexKeyFile, config.vertexProject) });
      names = chatNamer(chat, TOPIC_NAMING_MODEL);
    } else if (resolveEvidenceMode(process.env) !== 'off') {
      const { model, chat } = resolveEvidenceChat(config, process.env, { timeoutMs: 60_000, maxRetries: 1 });
      if (chat) names = chatNamer(chat, model);
    }
  } catch {
    names = undefined;
  }
  return {
    source: { space: index?.space() ?? null, vectorOf: (chunkId: number) => index?.get(chunkId) ?? null },
    ...(names ? { names } : {}),
  };
}

/** Registers memory_map. */
export function registerMemoryMapTool(ctx: ToolContext): void {
  const { jsonResult, server, mapContext, dashboard } = ctx;
  // Only the dashboard's own sessions see `groups`: an agent's tool listing stays as it was.
  const dashboardArgs: Record<string, z.ZodOptional<z.ZodBoolean>> = dashboard
    ? { groups: z.boolean().optional().describe('Also group every memory into topics and subtopics by meaning (the dashboard\'s topic map).') }
    : {};
  server.registerTool('memory_map', {
    title: 'Map everything this workspace holds',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Read-only overview for browsing, not for answering questions (use get_context for that): every memory (notes and daily-log entries), the things lifecycle facts are about, topics (tags), lifecycle facts with full history, grounded links between them (tag, wikilink, literal name mention, fact naming another thing), recent write events, and retired memories. A writerConflict line on a current fact means it replaced another agent\'s value until that agent saves it again. An imported memory carries origin: "import"; one whose stored source is a reserved identity (system, developer, assistant, Renor) is marked "untrusted": true. '
      + `limit bounds every list (memories, things, facts, links, events, retired), newest first (things by their newest fact; links shared across kinds): default ${DEFAULT_MAP_LIMIT}, at most ${MAX_LOOKUP_LIMIT}. total gives each list's size and truncated says which were cut; raise limit, or pass query. `
      + 'To find one memory to read, retire or restore, pass query (words it contains, e.g. "landlord"), and scope for one scope only: only memories and retired memories with one of the words are returned, rarest words first, then newest, up to limit. A note save returns the id of what it saved, so forgetting it needs no lookup.',
    inputSchema: {
      query: z.string().min(1).max(500).optional().describe('Words the memory contains. Matched at the start of words in each memory\'s text, title and path.'),
      scope: z.string().optional().describe('With query only: look in this memory scope ("global", or scope:<slug> / project:<slug>, which name the same folder for notes).'),
      limit: z.number().int().min(1).max(MAX_LOOKUP_LIMIT).optional().describe(`At most this many of each list the map shows (memories, things, facts, links, events, retired). Without a query, default ${DEFAULT_MAP_LIMIT}. With a query it bounds the memories and retired memories found, default ${DEFAULT_LOOKUP_LIMIT}.`),
      ...dashboardArgs,
    },
  }, async (args) => {
    try {
      if (args.query === undefined) {
        // The whole map holds things, facts, links and events too, and none of them is cut by scope: ignoring it would
        // answer for every scope.
        if (args.scope !== undefined) throw refusal('invalid_argument', 'memory_map takes a scope only with a query (words the memories contain): the whole map is not cut by scope');
        const wantsGroups = dashboard && (args as { groups?: boolean }).groups === true;
        const map = await buildMemoryMap(mapContext(), { limit: args.limit, ...(wantsGroups ? { groups: topicOptions(ctx) } : {}) });
        const memories = map.memories.map(markStoredMemory);
        // RENOR_RECALL_FILE_TREE (research lever, default off): a folder tree next to the list. Off, the reply is unchanged.
        return jsonResult(recallFileTreeOn() ? { ...map, memories, tree: memoryPathTree(map.memories) } : { ...map, memories });
      }
      // Read the way the facts lane reads a query: stop words count only when nothing else is left.
      const terms = factQueryTerms(args.query);
      if (terms.length === 0) throw refusal('invalid_argument', 'query has no word to look for (two or more letters or digits)');
      const scope = args.scope === undefined ? undefined : normalizeScope(args.scope);
      const found = await findMemories(mapContext(), { query: args.query, terms, limit: args.limit ?? DEFAULT_LOOKUP_LIMIT, scope });
      return jsonResult({ ...found, memories: found.memories.map(markStoredMemory) });
    } catch (err) {
      return toolError(err);
    }
  });
}
