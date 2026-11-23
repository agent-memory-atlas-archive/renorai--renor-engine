// ---------------------------------------------------------------------------
// The memory map's topics, kept between requests.
//
// Grouping a few thousand memories takes seconds (all pairs of vectors, then a
// model call to name the groups), so it is not redone on every dashboard load.
// The last grouping is cached in the index database with the centre of every
// subtopic. A memory saved since then joins the subtopic whose centre is
// nearest; a forgotten one leaves; an edited one (same id, new text or vector:
// a note's id is its path) leaves and joins again. Only when the memories have changed by more
// than REGROUP_SHARE since the last full grouping, or it is older than
// REGROUP_AFTER_MS, or the embedding space changed, is everything grouped and
// named again. Topics therefore stay where the person left them from one visit
// to the next, which is what makes a map learnable.
//
// The names come from a model when one is configured. The dashboard gives up
// on a reply after 12 seconds, so a request waits for the names only briefly
// (NAMING_WAIT_MS, and never past NAMING_DEADLINE_MS from its start): past that
// it answers with keyword names and the call finishes in the background,
// putting its names on the cached grouping for the next request. A call that
// failed is tried again by a later request, at most every NAMING_RETRY_MS.
//
// The cache is derived data: dropping the table only costs one regrouping. A
// permanent deletion drops it (memoryMap.ts, purgeRetired), and bumps the
// cache's epoch, so a grouping or naming already under way, computed from
// before the deletion, does not write back.
// ---------------------------------------------------------------------------

import crypto from 'node:crypto';
import type Database from '../db/sqlite.js';
import { applyNames, groupTopics, namingPlan, type GroupOptions, type TopicGroups, type TopicInput, type TopicNames } from './topics.js';

/** Regroup from scratch once this share of the memories was added or removed since the last full grouping. */
export const REGROUP_SHARE = 0.15;
/** Regroup from scratch at least this often, so names follow what the workspace is now about. */
export const REGROUP_AFTER_MS = 14 * 24 * 3600 * 1000;
const SIMILAR_PER_MEMORY = 3;
/** How long a request waits for the model's names before answering with keyword names. */
export const NAMING_WAIT_MS = 4000;
/** Nor past this long since the request began: grouping a large workspace takes seconds of its own. */
const NAMING_DEADLINE_MS = 7000;
/** A grouping left with keyword names asks the model again at most this often. */
export const NAMING_RETRY_MS = 10 * 60 * 1000;

export interface MemoryTopics extends TopicGroups {
  /** When the topics were last grouped from scratch. */
  groupedAt: string;
  /** Memories the map lists that have no stored vector yet (not grouped). */
  unplaced: number;
  /**
   * Every grouped memory, compactly, since the map's own list is cut to its limit: [id, title, at, source]. The dashboard
   * draws the topic map from these and reads a memory in full (read_memory) only when it is opened.
   */
  rows: Array<[string, string, string, string | null]>;
}

interface Cached {
  space: string;
  groupedAt: string;
  /** Memories at the last full grouping, and how many were added or removed since. */
  base: number;
  drift: number;
  /** The similarity at or above which two memories are listed as similar (fixed at the full grouping). */
  close: number;
  groups: TopicGroups;
  /** Per topic, per subtopic: its centre, a unit vector. */
  centres: number[][][];
  /** Each grouped memory's revision (revisionOf): a memory whose text or vector changed since is placed again. */
  rev: Record<string, string>;
  /** When the model was last asked to name this grouping. */
  namingTriedAt?: string;
}

/** Options for memoryTopics. `namingWaitMs` overrides how long a request waits for names (a test sets it). */
export type TopicOptions = GroupOptions & { now?: Date; namingWaitMs?: number };

export interface TopicSource {
  db: Database.Database;
  /** The embedding space every stored vector is in; null when the index holds none. */
  space: string | null;
  /** The stored vector of a chunk, or null. */
  vectorOf(chunkId: number): ArrayLike<number> | null;
}

/** Where a listed memory is in the index: the note its chunks are under, and for a daily entry its lines there. */
export interface MemoryIndexed {
  /** The index's key for the note (notes.path, chunks.note_path). */
  notePath: string;
  /** A daily entry: the [from, to) lines of the note's body it holds, as chunk start_line counts. Several if repeated. */
  lines?: Array<[number, number]>;
}

/** A memory the map lists, with the text grouping and naming read. */
export interface ListedMemory extends Partial<MemoryIndexed> { id: string; kind: string; path: string; text: string; title?: string; at?: string; source?: string | null }

function ensureTable(db: Database.Database): void {
  db.prepare('CREATE TABLE IF NOT EXISTS memory_topics_cache (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
}

function readCache(db: Database.Database): Cached | null {
  ensureTable(db);
  const row = db.prepare("SELECT value FROM memory_topics_cache WHERE key = 'current'").get() as { value: string } | undefined;
  if (!row) return null;
  try { return JSON.parse(row.value) as Cached; } catch { return null; }
}

/** The cache's epoch: bumped by every clear. A write computed under an older epoch is dropped. */
function readEpoch(db: Database.Database): number {
  ensureTable(db);
  const row = db.prepare("SELECT value FROM memory_topics_cache WHERE key = 'epoch'").get() as { value: string } | undefined;
  return row ? Number(row.value) || 0 : 0;
}

/** Write the cache, unless it was cleared since `epoch` was read. True when written. */
function writeCache(db: Database.Database, value: Cached, epoch: number): boolean {
  ensureTable(db);
  return db.transaction(() => {
    if (readEpoch(db) !== epoch) return false;
    db.prepare("INSERT INTO memory_topics_cache (key, value) VALUES ('current', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(JSON.stringify(value));
    return true;
  })();
}

/** Drop the cached topics (the next map with topics groups from scratch), and void every write computed before now. */
export function clearTopicCache(db: Database.Database): void {
  ensureTable(db);
  db.transaction(() => {
    db.prepare("DELETE FROM memory_topics_cache WHERE key = 'current'").run();
    db.prepare("INSERT INTO memory_topics_cache (key, value) VALUES ('epoch', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(String(readEpoch(db) + 1));
  })();
}

/** An entry's id from its exact stored bytes: the map's own rule (memoryMap.ts, entryId). */
function entryIdOf(rel: string, raw: string): string {
  return `entry:${rel}#${crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16)}`;
}

/**
 * A memory's revision: a hash of its text and of its vector to four decimals. A note keeps its id (its path) when it is
 * edited, so the id alone would leave an edited note in its old topic, with its old links.
 */
function revisionOf(text: string, vec: ArrayLike<number>): string {
  const h = crypto.createHash('sha256').update(text).update('\0');
  for (let i = 0; i < vec.length; i++) h.update(`${Math.round(vec[i] * 1e4)},`);
  return h.digest('hex').slice(0, 16);
}

function addInto(sum: Float32Array, v: ArrayLike<number>): void {
  for (let i = 0; i < sum.length; i++) sum[i] += v[i];
}

/**
 * Each listed memory's vector: a daily entry's is the mean of its chunks (one chunk per entry; a long entry is cut
 * into several), a note's is the mean of its chunks. A memory without a stored vector is left out.
 *
 * Chunks are found by where the listing says the memory is in the index (`notePath`, the index's own key) and an
 * entry's chunks by line: a chunk belongs to the entry whose lines it starts in (`lines`, counted as the indexer
 * counts them). Never by text: a chunk carries the entry's time and source line and the restored words, the listing
 * the statement alone, so the same entry reads differently in the two.
 */
export function memoryVectors(source: TopicSource, memories: ListedMemory[]): Map<string, Float32Array> {
  const out = new Map<string, Float32Array>();
  if (!source.space) return out;
  const byNote = new Map<string, ListedMemory[]>();
  for (const m of memories) {
    if ((m.kind !== 'entry' && m.kind !== 'note') || !m.notePath) continue;
    const list = byNote.get(m.notePath) ?? [];
    list.push(m);
    byNote.set(m.notePath, list);
  }
  const chunksOf = source.db.prepare('SELECT id, text, start_line FROM chunks WHERE note_path = ? ORDER BY start_line, id');
  for (const [notePath, listed] of byNote) {
    const chunks = chunksOf.all(notePath) as Array<{ id: number; text: string; start_line: number }>;
    const sums = new Map<string, { sum: Float32Array; count: number }>();
    const add = (id: string, v: ArrayLike<number>) => {
      const s = sums.get(id) ?? { sum: new Float32Array(v.length), count: 0 };
      addInto(s.sum, v);
      s.count++;
      sums.set(id, s);
    };
    const note = listed.find((m) => m.kind === 'note');
    const entries = listed.filter((m) => m.kind === 'entry');
    const rel = note ? null : listed[0].path;
    for (const c of chunks) {
      const v = source.vectorOf(c.id);
      if (!v || v.length === 0) continue;
      if (note) { add(note.id, v); continue; }
      const owner = entries.find((m) => m.lines?.some(([from, to]) => c.start_line >= from && c.start_line < to))
        // No lines (the listing could not say which line is which, and the indexer then cut the day by headings):
        // only a chunk that is an entry exactly, byte for byte, is that entry's.
        ?? entries.find((m) => !m.lines && rel !== null && entryIdOf(rel, c.text) === m.id);
      if (owner) add(owner.id, v);
    }
    for (const [id, s] of sums) {
      for (let i = 0; i < s.sum.length; i++) s.sum[i] /= s.count;
      out.set(id, s.sum);
    }
  }
  return out;
}

function unit(v: ArrayLike<number>): Float32Array {
  let s = 0;
  for (let i = 0; i < v.length; i++) s += v[i] * v[i];
  const inv = s > 0 ? 1 / Math.sqrt(s) : 0;
  const out = new Float32Array(v.length);
  for (let i = 0; i < v.length; i++) out[i] = v[i] * inv;
  return out;
}

function dot(a: ArrayLike<number>, b: ArrayLike<number>): number {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i] * b[i];
  return s;
}

function centresOf(groups: TopicGroups, vecs: Map<string, Float32Array>): number[][][] {
  const sums = groups.topics.map((t) => t.subs.map(() => null as Float32Array | null));
  for (const [id, [ti, si]] of Object.entries(groups.of)) {
    const v = vecs.get(id);
    if (!v) continue;
    const u = unit(v);
    const s = sums[ti][si] ?? new Float32Array(u.length);
    addInto(s, u);
    sums[ti][si] = s;
  }
  // Four decimals is plenty to find the nearest centre, and keeps the cached row small.
  return sums.map((subs) => subs.map((s) => (s ? Array.from(unit(s), (x) => Math.round(x * 1e4) / 1e4) : [])));
}

/** The closeness at or above which two memories count as similar: the one the grouping used (its 75th percentile). */
function closeOf(groups: TopicGroups): number {
  if (groups.similar.length === 0) return 1;
  return Math.min(...groups.similar.map((s) => s[2]));
}

function sizesFrom(groups: TopicGroups): void {
  for (const t of groups.topics) { t.size = 0; for (const s of t.subs) s.size = 0; }
  for (const [ti, si] of Object.values(groups.of)) {
    groups.topics[ti].size++;
    groups.topics[ti].subs[si].size++;
  }
}

let running: Promise<unknown> = Promise.resolve();

/**
 * The topics of `memories`: the cached grouping brought up to date, or a new grouping when there is none, it is stale,
 * or too much changed. Null when the workspace has too few memories with vectors for topics. Calls are serialized, so
 * two dashboard loads never group at once.
 */
export function memoryTopics(
  source: TopicSource,
  memories: ListedMemory[],
  options: TopicOptions = {},
): Promise<MemoryTopics | null> {
  const next = running.then(() => topicsNow(source, memories, options));
  running = next.catch(() => undefined);
  return next;
}

/** Naming calls under way, by database: one at a time per workspace. One from before a clear, or for another grouping, is never joined. */
const naming = new WeakMap<Database.Database, { epoch: number; groupedAt: string; job: Promise<TopicNames | null> }>();
const namingUnderWay = (db: Database.Database, epoch: number, groupedAt: string): boolean => {
  const n = naming.get(db);
  return n !== undefined && n.epoch === epoch && n.groupedAt === groupedAt;
};

/**
 * Ask the model to name `groups` and wait at most `waitMs`. Whenever the names come, they go on the cached grouping if it
 * is still this one (same groupedAt, no clear since `epoch`). Returns `groups` named, or as it was when the wait ran out.
 */
async function nameWithin(
  db: Database.Database, epoch: number, groupedAt: string, inputs: TopicInput[], groups: TopicGroups,
  namer: NonNullable<GroupOptions['names']>, waitMs: number,
): Promise<TopicGroups> {
  let job = namingUnderWay(db, epoch, groupedAt) ? naming.get(db)!.job : undefined;
  if (!job) {
    const plan = namingPlan(inputs, groups);
    const entry = { epoch, groupedAt, job: undefined as unknown as Promise<TopicNames | null> };
    job = namer(plan)
      .catch(() => null)
      .then((names) => {
        if (names) {
          db.transaction(() => {
            const c = readCache(db);
            if (!c || c.groupedAt !== groupedAt) return;
            applyNames(c.groups, names);
            writeCache(db, c, epoch);
          })();
        }
        return names;
      })
      .catch(() => null)
      .finally(() => { if (naming.get(db) === entry) naming.delete(db); });
    entry.job = job;
    naming.set(db, entry);
  }
  let wake: () => void = () => undefined;
  const late = new Promise<undefined>((resolve) => { wake = () => resolve(undefined); });
  const timer = setTimeout(() => wake(), Math.max(0, waitMs));
  const names = await Promise.race([job, late]);
  clearTimeout(timer);
  if (!names) return groups;
  const named = structuredClone(groups);
  applyNames(named, names);
  return named;
}

async function topicsNow(source: TopicSource, memories: ListedMemory[], options: TopicOptions): Promise<MemoryTopics | null> {
  const started = Date.now();
  const waitLeft = () => options.namingWaitMs ?? Math.max(0, Math.min(NAMING_WAIT_MS, NAMING_DEADLINE_MS - (Date.now() - started)));
  const now = options.now ?? new Date();
  const epoch = readEpoch(source.db);
  const inputsOf = (vecs: Map<string, Float32Array>): TopicInput[] =>
    memories.filter((m) => vecs.has(m.id)).map((m) => ({ id: m.id, text: m.text, vec: vecs.get(m.id)! }));
  const vecs = memoryVectors(source, memories);
  // Entries and notes only: nothing else the map lists (an observation) is ever embedded, so it is not waiting for a place.
  const unplaced = memories.filter((m) => (m.kind === 'entry' || m.kind === 'note') && !vecs.has(m.id)).length;
  if (!source.space) return null;
  const cached = readCache(source.db);
  const live = new Set(vecs.keys());
  const textOf = new Map(memories.map((m) => [m.id, m.text]));
  const rev: Record<string, string> = {};
  for (const [id, v] of vecs) rev[id] = revisionOf(textOf.get(id) ?? '', v);

  // A cache from before revisions were kept cannot tell an edited memory: group again.
  if (cached && cached.rev && cached.space === source.space && now.getTime() - Date.parse(cached.groupedAt) < REGROUP_AFTER_MS) {
    const groups = cached.groups;
    const added = [...live].filter((id) => !(id in groups.of));
    const removed = Object.keys(groups.of).filter((id) => !live.has(id));
    // Edited since: it leaves its place and joins again, as a new memory would. One change, not two.
    const edited = [...live].filter((id) => id in groups.of && cached.rev[id] !== rev[id]);
    const drift = cached.drift + added.length + removed.length + edited.length;
    if (drift <= cached.base * REGROUP_SHARE) {
      if (added.length > 0 || removed.length > 0 || edited.length > 0) {
        for (const id of [...removed, ...edited]) delete groups.of[id];
        const gone = new Set([...removed, ...edited]);
        groups.similar = groups.similar.filter(([a, b]) => !gone.has(a) && !gone.has(b));
        const all = [...live].map((id) => [id, unit(vecs.get(id)!)] as const);
        for (const id of [...added, ...edited]) {
          const u = all.find(([x]) => x === id)![1];
          let best: [number, number] = [0, 0], bestSim = -Infinity;
          cached.centres.forEach((subs, ti) => subs.forEach((c, si) => {
            if (c.length !== u.length) return;
            const s = dot(u, c);
            if (s > bestSim) { bestSim = s; best = [ti, si]; }
          }));
          groups.of[id] = best;
          // Its closest memories, if close enough to count as similar.
          const near = all.filter(([x]) => x !== id).map(([x, v]) => [x, dot(u, v)] as const)
            .filter(([, s]) => s >= cached.close).sort((a, b) => b[1] - a[1]).slice(0, SIMILAR_PER_MEMORY);
          for (const [x, s] of near) groups.similar.push([id, x, Math.round(s * 1000) / 1000]);
        }
        sizesFrom(groups);
        writeCache(source.db, { ...cached, drift, groups, rev }, epoch);
      }
      let shown = groups;
      // Still keyword names: the model failed or was slow last time. Ask again, now and then.
      const tried = cached.namingTriedAt ? Date.parse(cached.namingTriedAt) : -Infinity;
      if (options.names && groups.named === 'keywords' && (namingUnderWay(source.db, epoch, cached.groupedAt) || now.getTime() - tried >= NAMING_RETRY_MS)) {
        const latest = readCache(source.db);
        if (latest && !namingUnderWay(source.db, epoch, cached.groupedAt)) writeCache(source.db, { ...latest, namingTriedAt: now.toISOString() }, epoch);
        shown = await nameWithin(source.db, epoch, cached.groupedAt, inputsOf(vecs), groups, options.names, waitLeft());
      }
      return { ...shown, groupedAt: cached.groupedAt, unplaced, rows: rowsOf(memories, shown) };
    }
  }

  const inputs = inputsOf(vecs);
  // Keyword names first; the model's are asked for below, with a bound on the wait.
  const groups = await groupTopics(inputs);
  if (!groups) return null;
  const groupedAt = now.toISOString();
  const written = writeCache(source.db, {
    space: source.space, groupedAt, base: inputs.length, drift: 0, close: closeOf(groups), groups, centres: centresOf(groups, vecs), rev,
    ...(options.names ? { namingTriedAt: groupedAt } : {}),
  }, epoch);
  // Not written: a deletion happened while grouping. Nothing from before it goes to the model.
  const shown = options.names && written
    ? await nameWithin(source.db, epoch, groupedAt, inputs, groups, options.names, waitLeft())
    : groups;
  return { ...shown, groupedAt, unplaced, rows: rowsOf(memories, shown) };
}

function rowsOf(memories: ListedMemory[], groups: TopicGroups): MemoryTopics['rows'] {
  return memories.filter((m) => m.id in groups.of).map((m) => [m.id, (m.title ?? m.text).slice(0, 90), m.at ?? '', m.source ?? null]);
}
