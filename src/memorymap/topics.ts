// ---------------------------------------------------------------------------
// Topics: the memory map's memories grouped by what they are about, in two
// levels (topic → subtopic), for the dashboard's topic map.
//
// Grouping uses only the vectors the engine already stored for search (one per
// daily entry, the mean of its chunks for a note), so it calls no embedding
// model. A memory without a vector is left out and counted (`unplaced`).
//
//   1. Each memory's nearest neighbours by cosine similarity (brute force: the
//      map holds at most a few thousand memories).
//   2. A similarity graph of those neighbours, keeping the closer pairs, cut into
//      communities (Louvain). The resolution rises until the graph splits into
//      about as many sizeable topics as the workspace has room for.
//   3. Memories outside a sizeable community join the topic whose centre is
//      nearest; each topic is cut the same way into subtopics.
//
// Names come from `nameTopics` (a model, when one is configured) or, failing
// that, from the words that set a group apart (`keywordName`).
// ---------------------------------------------------------------------------

import { louvain } from './louvain.js';

export interface TopicInput {
  id: string;
  /** What the memory says (title and text); used for keyword names and model naming. */
  text: string;
  /** The memory's vector; any length, all inputs the same length. */
  vec: Float32Array;
}

export interface Subtopic { id: string; name: string; size: number }
export interface Topic { id: string; name: string; size: number; subs: Subtopic[] }

export interface TopicGroups {
  /** Topics, largest first. */
  topics: Topic[];
  /** For each grouped memory id: [topic index, subtopic index] into `topics` and its `subs`. */
  of: Record<string, [number, number]>;
  /** Pairs of memories that say nearly the same thing: [a, b, cosine rounded to 3 places]; at most SIMILAR_PER_MEMORY each. */
  similar: Array<[string, string, number]>;
  /** How the names were made. */
  named: 'model' | 'keywords';
}

/** Below this many memories there are no topics: the dashboard shows the memories by day instead. */
export const MIN_MEMORIES_FOR_TOPICS = 40;
const NEIGHBOURS = 10;
const SIMILAR_PER_MEMORY = 3;
const MAX_TOPICS = 10;
const MAX_SUBTOPICS = 8;
/** A topic smaller than this is not cut into subtopics: it is its own single subtopic. */
const MIN_TOPIC_FOR_SUBS = 24;

function normalize(v: Float32Array): Float32Array {
  let s = 0;
  for (let i = 0; i < v.length; i++) s += v[i] * v[i];
  const out = new Float32Array(v.length);
  const inv = s > 0 ? 1 / Math.sqrt(s) : 0;
  for (let i = 0; i < v.length; i++) out[i] = v[i] * inv;
  return out;
}

function dot(a: Float32Array, b: Float32Array): number {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i] * b[i];
  return s;
}

/** Each row's `k` nearest other rows: indexes and similarities, closest first. */
export async function nearest(vecs: Float32Array[], k: number): Promise<{ idx: Int32Array[]; sim: Float32Array[] }> {
  const n = vecs.length;
  const kk = Math.min(k, n - 1);
  const idx: Int32Array[] = [];
  const sim: Float32Array[] = [];
  const row = new Float32Array(n);
  // Compute the upper triangle once and fill both rows' heaps from it.
  const all: Float32Array[] = Array.from({ length: n }, () => new Float32Array(n));
  for (let i = 0; i < n; i++) {
    // Seconds of arithmetic for a large workspace: let the server answer other requests in between.
    if (i % 64 === 63) await new Promise((resolve) => setImmediate(resolve));
    const a = vecs[i];
    const ai = all[i];
    for (let j = i + 1; j < n; j++) {
      const s = dot(a, vecs[j]);
      ai[j] = s;
      all[j][i] = s;
    }
  }
  for (let i = 0; i < n; i++) {
    row.set(all[i]);
    row[i] = -Infinity;
    const order = Array.from({ length: n }, (_, j) => j).sort((x, y) => row[y] - row[x] || x - y).slice(0, kk);
    idx.push(Int32Array.from(order));
    sim.push(Float32Array.from(order.map((j) => row[j])));
  }
  return { idx, sim };
}

function quantile(values: number[], q: number): number {
  if (values.length === 0) return 0;
  const s = [...values].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.max(0, Math.floor(q * (s.length - 1))))];
}

interface Graph { n: number; edges: Array<[number, number, number]> }

/** The similarity graph among `members` (indexes into the whole set), renumbered 0..members.length-1. */
function subgraph(edges: Map<number, number>, n: number, members: number[]): Graph {
  const local = new Map<number, number>();
  members.forEach((m, i) => local.set(m, i));
  const out: Array<[number, number, number]> = [];
  for (const [key, w] of edges) {
    const a = Math.floor(key / n), b = key % n;
    const la = local.get(a), lb = local.get(b);
    if (la !== undefined && lb !== undefined) out.push([la, lb, w]);
  }
  return { n: members.length, edges: out };
}

function groupsOf(labels: Int32Array): number[][] {
  const g: number[][] = [];
  labels.forEach((c, i) => { (g[c] ??= []).push(i); });
  return g.filter(Boolean).sort((a, b) => b.length - a.length || a[0] - b[0]);
}

function centroid(vecs: Float32Array[], members: number[]): Float32Array {
  const c = new Float32Array(vecs[0].length);
  for (const m of members) for (let i = 0; i < c.length; i++) c[i] += vecs[m][i];
  return normalize(c);
}

/**
 * Cut `graph` into communities, raising the resolution until at least `want` of them hold `minSize` members or more.
 * When no resolution gets there (a small workspace: raising it further only crumbles every community below `minSize`),
 * the cut with the most sizeable communities is kept, the coarser one on a tie.
 * Returns the sizeable communities (largest first, at most `max`) and the members left over.
 */
function split(graph: Graph, want: number, minSize: number, max: number, start: number): { big: number[][]; rest: number[] } {
  let res = start;
  let best: number[][] = [];
  for (let step = 0; step < 30; step++) {
    const big = groupsOf(louvain(graph, res)).filter((g) => g.length >= minSize);
    if (big.length > best.length) best = big;
    if (big.length >= want) break;
    res *= 1.25;
  }
  const big = best.slice(0, max);
  const kept = new Set(big.flat());
  const rest: number[] = [];
  for (let i = 0; i < graph.n; i++) if (!kept.has(i)) rest.push(i);
  return { big, rest };
}

/** Assign each of `rest` to the group whose centre it is closest to. */
function joinNearest(vecs: Float32Array[], groups: number[][], rest: number[]): void {
  const centres = groups.map((g) => centroid(vecs, g));
  for (const r of rest) {
    let best = 0, bestSim = -Infinity;
    centres.forEach((c, gi) => {
      const s = dot(vecs[r], c);
      if (s > bestSim) { bestSim = s; best = gi; }
    });
    groups[best].push(r);
  }
}

/**
 * Merge groups (each a list of member lists) pairwise, closest centres first, until `target` remain. A pair's
 * closeness is discounted by its combined size, so small groups find a home before two big ones fuse.
 */
function mergeClosest(vecs: Float32Array[], groups: number[][][], target: number, n: number): number[][][] {
  const gs = groups.map((parts) => ({ parts, members: parts.flat(), c: centroid(vecs, parts.flat()) }));
  const fair = n / target;
  while (gs.length > target) {
    let bi = 0, bj = 1, best = -Infinity;
    for (let i = 0; i < gs.length; i++) {
      for (let j = i + 1; j < gs.length; j++) {
        const score = dot(gs[i].c, gs[j].c) - 0.12 * ((gs[i].members.length + gs[j].members.length) / fair);
        if (score > best) { best = score; bi = i; bj = j; }
      }
    }
    const parts = [...gs[bi].parts, ...gs[bj].parts];
    const members = parts.flat();
    gs.splice(bj, 1);
    gs[bi] = { parts, members, c: centroid(vecs, members) };
  }
  return gs.map((g) => g.parts);
}

/** How many topics a workspace of `n` memories has room for: about one per 250, from 3 to MAX_TOPICS. */
export function topicTarget(n: number): number {
  return Math.max(3, Math.min(MAX_TOPICS, Math.round(n / 250) + 2));
}

export interface GroupOptions {
  /** Name the groups; given each group's sample texts. Default: keyword names. */
  names?: (groups: Array<{ samples: string[]; subs: Array<{ samples: string[] }> }>) => Promise<{ topics: string[]; subs: string[][] } | null>;
}

/** Group memories into topics and subtopics. Null when there are too few memories for topics to mean anything. */
export async function groupTopics(inputs: TopicInput[], options: GroupOptions = {}): Promise<TopicGroups | null> {
  const n = inputs.length;
  if (n < MIN_MEMORIES_FOR_TOPICS) return null;
  const vecs = inputs.map((x) => normalize(x.vec));
  const { idx, sim } = await nearest(vecs, NEIGHBOURS);

  // Keep the closer pairs: a neighbour below the 30th percentile of all neighbour similarities is noise, whatever
  // model made the vectors (absolute cosines differ a lot between models).
  const allSims: number[] = [];
  for (const s of sim) for (const x of s) allSims.push(x);
  const floor = quantile(allSims, 0.3);
  const edges = new Map<number, number>();
  for (let i = 0; i < n; i++) {
    for (let e = 0; e < idx[i].length; e++) {
      const j = idx[i][e], s = sim[i][e];
      if (s < floor) continue;
      const key = i < j ? i * n + j : j * n + i;
      // A pair both sides chose counts twice: mutual neighbours bind harder.
      edges.set(key, (edges.get(key) ?? 0) + Math.max(0.01, s - floor + 0.05));
    }
  }
  const whole: Graph = { n, edges: [...edges].map(([key, w]) => [Math.floor(key / n), key % n, w]) };

  const target = topicTarget(n);
  // Cut finer than wanted, then merge the closest groups: Louvain alone leaves one giant topic beside several crumbs of
  // the same subject, while merging by centre gives topics of comparable size. The fine groups become the subtopics.
  const fine = split(whole, Math.round(target * 2.5), Math.max(6, Math.round(n / 150)), 48, 0.1);
  if (fine.big.length === 0) return null;
  joinNearest(vecs, fine.big, fine.rest);
  const topGroups = mergeClosest(vecs, fine.big.map((g) => [g]), target, n);

  const subsOf: number[][][] = topGroups.map((parts) => {
    let subs = parts.map((p) => p.flat());
    if (subs.length === 1 && subs[0].length >= MIN_TOPIC_FOR_SUBS) {
      const members = subs[0];
      const g = subgraph(edges, n, members);
      const want = Math.min(MAX_SUBTOPICS, Math.max(2, Math.round(members.length / 60)));
      const s = split(g, want, Math.max(4, Math.round(members.length / 40)), MAX_SUBTOPICS, 0.5);
      if (s.big.length >= 2) {
        subs = s.big.map((grp) => grp.map((li) => members[li]));
        joinNearest(vecs, subs, s.rest.map((li) => members[li]));
      }
    }
    if (subs.length > MAX_SUBTOPICS) subs = mergeClosest(vecs, subs.map((x) => [x]), MAX_SUBTOPICS, n).map((p) => p.flat());
    return subs.sort((a, b) => b.length - a.length || a[0] - b[0]);
  });
  const topMembers = subsOf.map((subs) => subs.flat());
  const order = topMembers.map((_, i) => i).sort((a, b) => topMembers[b].length - topMembers[a].length || a - b);
  const top = { big: order.map((i) => topMembers[i]) };
  subsOf.splice(0, subsOf.length, ...order.map((i) => subsOf[i]));

  // Samples for naming: the members closest to each group's centre.
  const samplesOf = (members: number[], k: number): string[] => {
    const c = centroid(vecs, members);
    return [...members].sort((a, b) => dot(vecs[b], c) - dot(vecs[a], c) || a - b).slice(0, k).map((m) => inputs[m].text.slice(0, 200));
  };
  const plan = top.big.map((members, ti) => ({ samples: samplesOf(members, 14), subs: subsOf[ti].map((s) => ({ samples: samplesOf(s, 6) })) }));
  const texts = inputs.map((x) => x.text);
  const kw = keywordNamer(texts);

  const topics: Topic[] = top.big.map((members, ti) => ({
    id: `t${ti}`,
    name: kw(members),
    size: members.length,
    subs: subsOf[ti].map((s, si) => ({
      id: `t${ti}s${si}`,
      name: subsOf[ti].length === 1 ? kw(members) : kw(s, members),
      size: s.length,
    })),
  }));
  const of: Record<string, [number, number]> = {};
  subsOf.forEach((subs, ti) => subs.forEach((s, si) => { for (const m of s) of[inputs[m].id] = [ti, si]; }));

  const similar: Array<[string, string, number]> = [];
  const seen = new Set<number>();
  const close = quantile(allSims, 0.75);
  for (let i = 0; i < n; i++) {
    for (let e = 0; e < Math.min(SIMILAR_PER_MEMORY, idx[i].length); e++) {
      const j = idx[i][e], s = sim[i][e];
      if (s < close) break;
      const key = i < j ? i * n + j : j * n + i;
      if (seen.has(key)) continue;
      seen.add(key);
      similar.push([inputs[i].id, inputs[j].id, Math.round(s * 1000) / 1000]);
    }
  }
  const groups: TopicGroups = { topics, of, similar, named: 'keywords' };
  if (options.names) {
    try {
      const names = await options.names(plan);
      if (names) applyNames(groups, names);
    } catch {
      // Keyword names stay.
    }
  }
  return groups;
}

export type TopicNames = { topics: string[]; subs: string[][] };
export type NamingPlan = Array<{ samples: string[]; subs: Array<{ samples: string[] }> }>;

/** Put a namer's names on `groups`, keeping the keyword name wherever it gave none. A lone subtopic is its topic. */
export function applyNames(groups: TopicGroups, names: TopicNames): void {
  groups.topics.forEach((t, ti) => {
    const name = names.topics[ti];
    if (name) t.name = name;
    t.subs.forEach((s, si) => {
      const sub = t.subs.length === 1 ? name : names.subs[ti]?.[si];
      if (sub) s.name = sub;
    });
  });
  groups.named = 'model';
}

/**
 * What a namer is shown for `groups`, rebuilt from its members: per topic the 14 memories closest to its centre, per
 * subtopic 6. The same samples groupTopics gives, so a grouping named later is named from what it would have been.
 */
export function namingPlan(inputs: TopicInput[], groups: TopicGroups): NamingPlan {
  const vecs = inputs.map((x) => normalize(x.vec));
  const index = new Map(inputs.map((x, i) => [x.id, i]));
  const members = groups.topics.map((t) => t.subs.map(() => [] as number[]));
  for (const [id, [ti, si]] of Object.entries(groups.of)) {
    const i = index.get(id);
    if (i !== undefined && members[ti]?.[si]) members[ti][si].push(i);
  }
  const samplesOf = (list: number[], k: number): string[] => {
    if (list.length === 0) return [];
    const c = centroid(vecs, list);
    return [...list].sort((a, b) => dot(vecs[b], c) - dot(vecs[a], c) || a - b).slice(0, k).map((m) => inputs[m].text.slice(0, 200));
  };
  return members.map((subs) => ({ samples: samplesOf(subs.flat(), 14), subs: subs.map((s) => ({ samples: samplesOf(s, 6) })) }));
}

// ------------------------------- keyword names -------------------------------

const STOP = new Set(`a about above after again against all also am an and any are as at be because been before being below between both but by can could did do does doing done down during each few for from further had has have having he her here hers him his how i if in into is it its itself just like me more most my no nor not now of off on once only or other our ours out over own same she should so some such than that the their theirs them then there these they this those through to too under until up us very was we were what when where which while who whom why will with would you your yours
  saved save says said use used using new one two get got make made via per vs etc yes ok also still need needs want wants user users renor agent agents memory memories claude codex today yesterday tomorrow`.split(/\s+/));

function words(text: string): string[] {
  return (text.toLowerCase().match(/[a-z][a-z0-9-]{2,}/g) ?? []).filter((w) => !STOP.has(w) && !/^\d/.test(w) && w.length <= 24);
}

/**
 * Names a group by the words that set it apart from `among` (default: everything): a word frequent in the group and
 * rare outside it. Returns up to three words, the first capitalised ("Billing, invoices and paddle").
 */
export function keywordNamer(texts: string[]): (members: number[], among?: number[]) => string {
  const docWords = texts.map((t) => new Set(words(t)));
  const df = new Map<string, number>();
  for (const ws of docWords) for (const w of ws) df.set(w, (df.get(w) ?? 0) + 1);
  return (members, among) => {
    const tf = new Map<string, number>();
    for (const m of members) for (const w of docWords[m]) tf.set(w, (tf.get(w) ?? 0) + 1);
    let base = df, total = texts.length;
    if (among) {
      base = new Map();
      for (const m of among) for (const w of docWords[m]) base.set(w, (base.get(w) ?? 0) + 1);
      total = among.length;
    }
    const scored = [...tf]
      .filter(([, c]) => c >= Math.max(2, members.length * 0.04))
      .map(([w, c]) => [w, (c / members.length) * Math.log((total + 1) / ((base.get(w) ?? 0) + 1))] as const)
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const picked: string[] = [];
    for (const [w] of scored) {
      if (picked.some((p) => p.startsWith(w.slice(0, 5)) || w.startsWith(p.slice(0, 5)))) continue;
      picked.push(w);
      if (picked.length === 3) break;
    }
    if (picked.length === 0) return 'Other';
    const list = picked.length === 1 ? picked[0] : `${picked.slice(0, -1).join(', ')} and ${picked[picked.length - 1]}`;
    return list.charAt(0).toUpperCase() + list.slice(1);
  };
}

// -------------------------------- model names --------------------------------

/** The most characters a name may have; a longer reply is not a name. */
const MAX_NAME_CHARS = 40;

export interface NamingChat {
  (request: {
    model: string;
    messages: Array<{ role: 'user' | 'system'; content: string }>;
    temperature: 0;
    response_format?: { type: 'json_object' };
    max_tokens?: number;
  }): Promise<{ content: string }>;
}

const NAMING_SYSTEM = `You name the topics of one person's saved memories, so they can find their way around a map of them.
You get numbered topics. Each has sample memories and numbered subtopics with their own samples.
Give every topic and every subtopic a short name:
- 1 to 4 words, sentence case, no quotes, no trailing punctuation, no emoji.
- Say what the memories are about, the way the person would say it ("Billing and deploys", "Leads and outreach").
- Never "Memories about", "Notes on", "Misc" or "Various"; never repeat the topic's name for a subtopic.
- All names distinct. Use the language most samples are written in.
Reply with JSON only: {"topics":[{"name":"...","subs":["...", "..."]}]} with the topics and subtopics in the order given.`;

function cleanName(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.replace(/["“”]/g, '').replace(/[.:;,!]+$/, '').replace(/\s+/g, ' ').trim();
  if (!s || s.length > MAX_NAME_CHARS) return null;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Names groups with one model call. Null (keyword names are used) when the reply does not fit the groups. */
export function chatNamer(chat: NamingChat, model: string): NonNullable<GroupOptions['names']> {
  return async (groups) => {
    const prompt = groups.map((g, ti) => [
      `Topic ${ti + 1}:`,
      ...g.samples.slice(0, 10).map((s) => `  - ${s.replace(/\s+/g, ' ').slice(0, 160)}`),
      ...g.subs.map((sub, si) => [
        `  Subtopic ${ti + 1}.${si + 1}:`,
        ...sub.samples.slice(0, 5).map((s) => `    - ${s.replace(/\s+/g, ' ').slice(0, 120)}`),
      ].join('\n')),
    ].join('\n')).join('\n\n');
    const reply = await chat({
      model,
      messages: [{ role: 'system', content: NAMING_SYSTEM }, { role: 'user', content: prompt }],
      temperature: 0,
      response_format: { type: 'json_object' },
      max_tokens: 2000,
    });
    const text = reply.content.trim().replace(/^```(?:json)?\s*/i, '').replace(/```$/, '');
    let parsed: { topics?: Array<{ name?: unknown; subs?: unknown }> };
    try { parsed = JSON.parse(text); } catch { return null; }
    if (!Array.isArray(parsed.topics) || parsed.topics.length !== groups.length) return null;
    const topics: string[] = [];
    const subs: string[][] = [];
    for (let ti = 0; ti < groups.length; ti++) {
      const t = parsed.topics[ti];
      const name = cleanName(t?.name);
      if (!name) return null;
      topics.push(name);
      const raw = Array.isArray(t.subs) ? t.subs : [];
      subs.push(groups[ti].subs.map((_, si) => cleanName(raw[si]) ?? ''));
    }
    return { topics, subs };
  };
}
