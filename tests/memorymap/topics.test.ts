import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type Database from '../../src/db/sqlite';
import { openDb } from '../../src/db/client';
import { runMigrations } from '../../src/db/schema';
import { indexVault } from '../../src/indexer/pipeline';
import { DEFAULT_LEDGER_REL } from '../../src/memory/lifecycle';
import { engineDailyHeader, formatEntry } from '../../src/memory/dailyNote';
import { buildMemoryMap, purgeRetired, retireMemory, topicListing, type MemoryMapContext } from '../../src/memorymap/memoryMap';
import { louvain } from '../../src/memorymap/louvain';
import { chatNamer, groupTopics, keywordNamer, MIN_MEMORIES_FOR_TOPICS, type TopicInput } from '../../src/memorymap/topics';
import { clearTopicCache, memoryVectors, NAMING_RETRY_MS, REGROUP_AFTER_MS, type TopicOptions, type TopicSource } from '../../src/memorymap/topicStore';

// The dashboard's topic map: memories grouped by the vectors the engine already stored. Synthetic vectors only: four
// subjects, each a direction in space plus seeded noise, so which memory belongs with which is known in advance.

const SUBJECTS = [
  { word: 'billing', lines: ['invoice for the pro plan', 'checkout failed on paddle', 'refund the annual billing plan', 'billing portal link'] },
  { word: 'garden', lines: ['water the tomatoes', 'garden beds need compost', 'prune the roses in the garden', 'seeds for the garden'] },
  { word: 'travel', lines: ['flight to lisbon booked', 'hotel near the station', 'travel insurance renewed', 'passport for travel'] },
  { word: 'climbing', lines: ['bouldering gym on tuesday', 'new climbing shoes', 'climbing trip to the crag', 'chalk bag for climbing'] },
];
const DIM = 32;

/** A seeded generator, so every run draws the same noise. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function vectorFor(subject: number, rand: () => number): Float32Array {
  const v = new Float32Array(DIM);
  v[subject * 4] = 1;
  v[subject * 4 + 1] = 0.6;
  for (let i = 0; i < DIM; i++) v[i] += (rand() - 0.5) * 0.5;
  return v;
}

function synthetic(perSubject: number, seed = 7): Array<TopicInput & { subject: number }> {
  const rand = rng(seed);
  const out: Array<TopicInput & { subject: number }> = [];
  for (let k = 0; k < perSubject; k++) {
    SUBJECTS.forEach((s, subject) => {
      out.push({ id: `m${subject}-${k}`, subject, text: `${s.lines[k % s.lines.length]} (${k})`, vec: vectorFor(subject, rand) });
    });
  }
  return out;
}

describe('louvain', () => {
  it('splits two cliques joined by one weak edge, the same way every time', () => {
    const edges: Array<[number, number, number]> = [];
    for (const base of [0, 5]) for (let i = 0; i < 5; i++) for (let j = i + 1; j < 5; j++) edges.push([base + i, base + j, 1]);
    edges.push([4, 5, 0.1]);
    const a = louvain({ n: 10, edges });
    expect(Array.from(a)).toEqual([0, 0, 0, 0, 0, 1, 1, 1, 1, 1]);
    expect(Array.from(louvain({ n: 10, edges }))).toEqual(Array.from(a));
  });

  it('leaves a node without edges on its own', () => {
    expect(Array.from(louvain({ n: 3, edges: [[0, 1, 1]] }))).toEqual([0, 0, 1]);
  });
});

describe('groupTopics', () => {
  it('has no topics below the minimum number of memories', async () => {
    expect(await groupTopics(synthetic(Math.floor((MIN_MEMORIES_FOR_TOPICS - 1) / 4)))).toBeNull();
  });

  it('puts memories about one subject in one topic, and every memory somewhere', async () => {
    const inputs = synthetic(40);
    const groups = (await groupTopics(inputs))!;
    expect(groups).not.toBeNull();
    expect(Object.keys(groups.of).sort()).toEqual(inputs.map((x) => x.id).sort());
    // Each subject's memories: nearly all in that subject's most common topic.
    for (let subject = 0; subject < SUBJECTS.length; subject++) {
      const topicsOf = inputs.filter((x) => x.subject === subject).map((x) => groups.of[x.id][0]);
      const counts = new Map<number, number>();
      for (const t of topicsOf) counts.set(t, (counts.get(t) ?? 0) + 1);
      expect(Math.max(...counts.values()) / topicsOf.length).toBeGreaterThanOrEqual(0.9);
    }
    // Sizes add up, largest first, and keyword names (no model) name the subject.
    expect(groups.topics.reduce((s, t) => s + t.size, 0)).toBe(inputs.length);
    for (const t of groups.topics) expect(t.subs.reduce((s, x) => s + x.size, 0)).toBe(t.size);
    expect(groups.topics.map((t) => t.size)).toEqual(groups.topics.map((t) => t.size).sort((a, b) => b - a));
    expect(groups.named).toBe('keywords');
    const names = groups.topics.map((t) => t.name.toLowerCase()).join(' | ');
    for (const s of SUBJECTS) expect(names).toContain(s.word);
  });

  it('finds topics in a small workspace whose subjects cannot be cut as finely as wanted', async () => {
    // Four subjects of 10 to 30 memories: the cut never reaches the wanted count, so the best one seen is kept.
    for (const per of [10, 11, 12, 20, 30]) {
      const inputs = synthetic(per);
      const groups = await groupTopics(inputs);
      expect(groups, `${per * 4} memories`).not.toBeNull();
      expect(Object.keys(groups!.of).length).toBe(inputs.length);
      expect(groups!.topics.length).toBeGreaterThanOrEqual(2);
    }
  });

  it('gives the same topics for the same memories', async () => {
    const a = await groupTopics(synthetic(30));
    const b = await groupTopics(synthetic(30));
    expect(b).toEqual(a);
  });

  it('lists similar pairs only between memories that are close', async () => {
    const inputs = synthetic(30);
    const groups = (await groupTopics(inputs))!;
    const subjectOf = new Map(inputs.map((x) => [x.id, x.subject]));
    expect(groups.similar.length).toBeGreaterThan(0);
    for (const [a, b] of groups.similar) expect(subjectOf.get(a)).toBe(subjectOf.get(b));
  });

  it('uses the names a namer gives, and keyword names when it fails', async () => {
    const inputs = synthetic(30);
    const named = (await groupTopics(inputs, {
      names: async (plan) => ({ topics: plan.map((_, i) => `Topic ${i + 1}`), subs: plan.map((g) => g.subs.map((_, j) => `Part ${j + 1}`)) }),
    }))!;
    expect(named.named).toBe('model');
    expect(named.topics.map((t) => t.name)).toEqual(named.topics.map((_, i) => `Topic ${i + 1}`));
    const failed = (await groupTopics(inputs, { names: async () => { throw new Error('provider down'); } }))!;
    expect(failed.named).toBe('keywords');
  });
});

describe('chatNamer', () => {
  const plan = [{ samples: ['a'], subs: [{ samples: ['a1'] }, { samples: ['a2'] }] }, { samples: ['b'], subs: [{ samples: ['b1'] }] }];

  it('reads the model reply into names, cleaned', async () => {
    const namer = chatNamer(async () => ({ content: '```json\n{"topics":[{"name":"\\"billing and deploys.\\"","subs":["paddle checkout","refunds"]},{"name":"garden","subs":["beds"]}]}\n```' }), 'm');
    expect(await namer(plan)).toEqual({ topics: ['Billing and deploys', 'Garden'], subs: [['Paddle checkout', 'Refunds'], ['Beds']] });
  });

  it('refuses a reply that does not fit the groups', async () => {
    expect(await chatNamer(async () => ({ content: '{"topics":[{"name":"only one"}]}' }), 'm')(plan)).toBeNull();
    expect(await chatNamer(async () => ({ content: 'not json' }), 'm')(plan)).toBeNull();
    const long = 'x'.repeat(80);
    expect(await chatNamer(async () => ({ content: `{"topics":[{"name":"${long}"},{"name":"b"}]}` }), 'm')(plan)).toBeNull();
  });
});

describe('keywordNamer', () => {
  it('names a group by the words that set it apart', () => {
    const name = keywordNamer(['paddle invoice due', 'paddle refund sent', 'water the garden', 'garden compost'])([0, 1]);
    expect(name.toLowerCase()).toContain('paddle');
    expect(name.toLowerCase()).not.toContain('garden');
  });
});

describe('the memory map with topics', () => {
  let vault: string;
  let db: Database.Database;
  let ctx: MemoryMapContext;
  let source: Omit<TopicSource, 'db'>;
  let namerCalls: number;
  const rand = rng(11);
  const vectorOfText = new Map<string, Float32Array>();

  /** Each chunk's vector: its subject's direction (found by the subject's word in its text) plus noise. */
  function chunkVector(text: string): Float32Array | null {
    const subject = SUBJECTS.findIndex((s) => s.lines.some((l) => text.includes(l)));
    if (subject < 0) return null;
    if (!vectorOfText.has(text)) vectorOfText.set(text, vectorFor(subject, rand));
    return vectorOfText.get(text)!;
  }

  function writeDay(day: string, entries: string[]): void {
    const rel = `Memory/Daily/${day}.md`;
    fs.mkdirSync(path.join(vault, path.dirname(rel)), { recursive: true });
    fs.writeFileSync(path.join(vault, rel), engineDailyHeader(day)
      + entries.map((text, i) => formatEntry(`09:${String(i % 60).padStart(2, '0')}:00`, 'cli', text, false)).join('\n') + '\n');
  }

  async function map() {
    return buildMemoryMap(ctx, {
      limit: 5,
      groups: {
        source,
        names: async (plan) => {
          namerCalls++;
          return { topics: plan.map((_, i) => `Named ${i + 1}`), subs: plan.map((g) => g.subs.map((_, j) => `Sub ${j + 1}`)) };
        },
      },
    });
  }

  type Namer = NonNullable<TopicOptions['names']>;
  async function mapWith(names: Namer, extra: Omit<TopicOptions, 'names'> = {}) {
    return buildMemoryMap(ctx, { limit: 5, groups: { source, names, ...extra } });
  }
  /** The cached grouping as stored, or null. */
  function stored(): string | null {
    const row = db.prepare("SELECT value FROM memory_topics_cache WHERE key = 'current'").get() as { value: string } | undefined;
    return row?.value ?? null;
  }
  const settle = () => new Promise((resolve) => setTimeout(resolve, 20));
  /** Wait until `ready` holds (a grouping takes longer on a loaded machine), up to ten seconds. */
  const until = async (ready: () => boolean) => { for (let i = 0; i < 500 && !ready(); i++) await settle(); };
  /** A namer that answers only when told to. */
  function held(): { names: Namer; answer: (topics: string) => void; calls: () => number } {
    let calls = 0;
    let release: (v: { topics: string[]; subs: string[][] }) => void = () => undefined;
    let plan: Parameters<Namer>[0] = [];
    return {
      names: (p) => { calls++; plan = p; return new Promise((resolve) => { release = resolve; }); },
      answer: (topics) => release({ topics: plan.map((_, i) => `${topics} ${i + 1}`), subs: plan.map((g) => g.subs.map((_, j) => `${topics} sub ${j + 1}`)) }),
      calls: () => calls,
    };
  }

  beforeEach(async () => {
    vault = fs.mkdtempSync(path.join(os.tmpdir(), 'map-topics-'));
    db = openDb(path.join(vault, '.memory-index', 'index.db'));
    runMigrations(db);
    ctx = { db, memoryDir: vault, ledgerRelPath: DEFAULT_LEDGER_REL, indexOptions: {} };
    namerCalls = 0;
    const texts = (from: number, count: number) => Array.from({ length: count }, (_, k) => {
      const s = SUBJECTS[(from + k) % 4];
      return `${s.lines[(from + k) % s.lines.length]} #${from + k}`;
    });
    // 120 entries over three days.
    writeDay('2026-10-01', texts(0, 40));
    writeDay('2026-10-02', texts(40, 40));
    writeDay('2026-10-03', texts(80, 40));
    await indexVault(db, vault, {});
    const textOf = db.prepare('SELECT text FROM chunks WHERE id = ?');
    source = {
      space: 'test-space',
      vectorOf: (id) => {
        const row = textOf.get(id) as { text: string } | undefined;
        return row ? chunkVector(row.text) : null;
      },
    };
  });
  afterEach(() => {
    db.close();
    fs.rmSync(vault, { recursive: true, force: true });
  });

  it('gives every daily entry the vector of its own chunk', async () => {
    const vecs = memoryVectors({ ...source, db }, await topicListing(ctx));
    expect(vecs.size).toBe(120);
  });

  it('gives an entry cut into several chunks the mean of all of them, by line, whatever its pieces say', async () => {
    const unitAt = (i: number) => { const v = new Float32Array(DIM); v[i] = 1; return v; };
    const marks: Record<string, Float32Array> = { '[A]': unitAt(20), '[B]': unitAt(21), '[C]': unitAt(22), '[D]': unitAt(23), '[E]': unitAt(24) };
    const day = [
      // Cut in two: its first piece holds the time and source line, which the listed statement does not.
      formatEntry('11:00:00', 'cli', 'water the tomatoes [A] with the long hose before the sun is high\n\nand then [B] look under every leaf in the beds for slugs after the rain', false),
      // Its last piece is under 20 characters.
      formatEntry('11:01:00', 'cli', 'invoice for the pro plan [C] went out to the customer with the annual discount applied\n\nok [D]', false),
      // Stored with a line escaped (it looks like an entry); the index holds it restored.
      formatEntry('11:02:00', 'cli', 'flight to lisbon booked [E]\n- [12:00:00] (cli) a line that looks like an entry', true),
    ];
    fs.writeFileSync(path.join(vault, 'Memory/Daily/2026-10-06.md'), engineDailyHeader('2026-10-06') + day.join('\n') + '\n');
    await indexVault(db, vault, { chunkOptions: { maxTokens: 12 } });
    const textOf = db.prepare('SELECT text FROM chunks WHERE id = ?');
    const vectorOf = (id: number) => {
      const text = (textOf.get(id) as { text: string } | undefined)?.text ?? '';
      const mark = Object.keys(marks).find((m) => text.includes(m));
      return mark ? marks[mark] : source.vectorOf(id);
    };
    const pieces = db.prepare("SELECT text FROM chunks WHERE note_path LIKE '%2026-10-06.md' ORDER BY start_line").all() as Array<{ text: string }>;
    expect(pieces.filter((c) => /\[[ABCD]\]/.test(c.text)).length).toBe(4);
    expect(pieces.find((c) => c.text.includes('[D]'))!.text.trim().length).toBeLessThan(20);

    const listed = await topicListing(ctx);
    const vecs = memoryVectors({ ...source, db, vectorOf }, listed);
    const idOf = (mark: string) => listed.find((m) => m.text.includes(mark))!.id;
    const mean = (a: Float32Array, b: Float32Array) => Array.from(a, (x, i) => (x + b[i]) / 2);
    expect(Array.from(vecs.get(idOf('[A]'))!)).toEqual(mean(marks['[A]'], marks['[B]']));
    expect(Array.from(vecs.get(idOf('[C]'))!)).toEqual(mean(marks['[C]'], marks['[D]']));
    expect(Array.from(vecs.get(idOf('[E]'))!)).toEqual(Array.from(marks['[E]']));
    // Every other entry still has its own chunk's vector.
    expect(vecs.size).toBe(123);
  });

  it('never gives an entry its neighbour\'s vector when the day changed after it was indexed', async () => {
    const rel = 'Memory/Daily/2026-10-01.md';
    const before = await topicListing(ctx);
    const own = memoryVectors({ ...source, db }, before);
    // An entry written above the others, not indexed yet: every line below it moved down by one.
    const file = path.join(vault, rel);
    const text = fs.readFileSync(file, 'utf8');
    const at = text.indexOf('- [');
    fs.writeFileSync(file, text.slice(0, at) + formatEntry('08:59:00', 'cli', 'prune the roses in the garden, early', false) + '\n' + text.slice(at));
    const vecs = memoryVectors({ ...source, db }, await topicListing(ctx));
    for (const m of before.filter((x) => x.path === rel)) {
      if (vecs.has(m.id)) expect(Array.from(vecs.get(m.id)!)).toEqual(Array.from(own.get(m.id)!));
    }
    expect(before.filter((x) => x.path === rel && vecs.has(x.id)).length).toBe(40);
  });

  it('groups every memory, not only the ones the reply lists, and names them once', async () => {
    const reply = await map();
    expect(reply.memories.length).toBe(5);
    expect(reply.groups).toBeTruthy();
    expect(Object.keys(reply.groups!.of).length).toBe(120);
    expect(reply.groups!.unplaced).toBe(0);
    expect(reply.groups!.rows.length).toBe(120);
    expect(new Set(reply.groups!.rows.map((r) => r[0]))).toEqual(new Set(Object.keys(reply.groups!.of)));
    expect(reply.groups!.topics[0].name).toBe('Named 1');
    expect(namerCalls).toBe(1);
    // A second read uses the cache: no model call, same topics.
    const again = await map();
    expect(namerCalls).toBe(1);
    expect(again.groups!.of).toEqual(reply.groups!.of);
  });

  it('places a few new memories into the existing topics without grouping again', async () => {
    const before = await map();
    writeDay('2026-10-04', ['water the tomatoes again #200', 'invoice for the pro plan again #201']);
    await indexVault(db, vault, {});
    const after = await map();
    expect(namerCalls).toBe(1);
    expect(Object.keys(after.groups!.of).length).toBe(122);
    expect(after.groups!.groupedAt).toBe(before.groups!.groupedAt);
    // The new garden memory joins the topic holding the other garden memories.
    const all = (await buildMemoryMap(ctx, { limit: 500 })).memories;
    const topicOf = (m: { id: string }) => after.groups!.of[m.id][0];
    const fresh = all.find((m) => m.title.includes('tomatoes again'))!;
    const older = all.filter((m) => m.title.includes('garden beds need compost #'));
    expect(older.length).toBeGreaterThan(0);
    expect(topicOf(fresh)).toBe(topicOf(older[0]));
    const sizes = after.groups!.topics.reduce((s, t) => s + t.size, 0);
    expect(sizes).toBe(122);
  });

  it('moves an edited note to the topic of its new text, without grouping again', async () => {
    const note = (line: string) => {
      fs.mkdirSync(path.join(vault, 'Notes'), { recursive: true });
      fs.writeFileSync(path.join(vault, 'Notes', 'plan.md'), `# Plan\n\n${line} for the week, written down.\n`);
    };
    note('water the tomatoes');
    await indexVault(db, vault, {});
    const before = await map();
    const all = (await buildMemoryMap(ctx, { limit: 500 })).memories;
    const topicOf = (groups: typeof before.groups, find: string) => groups!.of[all.find((m) => m.title.includes(find))!.id][0];
    expect(before.groups!.of['note:Notes/plan.md']).toBeDefined();
    expect(before.groups!.of['note:Notes/plan.md'][0]).toBe(topicOf(before.groups, 'garden beds need compost #'));
    // Same id (a note's id is its path), new text and vector.
    note('invoice for the pro plan');
    await indexVault(db, vault, {});
    const after = await map();
    expect(namerCalls).toBe(1);
    expect(after.groups!.groupedAt).toBe(before.groups!.groupedAt);
    expect(after.groups!.of['note:Notes/plan.md'][0]).toBe(topicOf(after.groups, 'invoice for the pro plan #'));
    // Its similar links are the new ones: every pair it is in now joins it to a billing memory.
    const billing = new Set(all.filter((m) => SUBJECTS[0].lines.some((l) => m.title.includes(l))).map((m) => m.id));
    const pairs = after.groups!.similar.filter(([a, b]) => a === 'note:Notes/plan.md' || b === 'note:Notes/plan.md');
    for (const [a, b] of pairs) expect(billing.has(a === 'note:Notes/plan.md' ? b : a)).toBe(true);
  });

  it('answers with keyword names in time when the namer never answers, and the next request gets its names', async () => {
    const namer = held();
    const t0 = Date.now();
    const first = await mapWith(namer.names, { namingWaitMs: 100 });
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(first.groups!.named).toBe('keywords');
    expect(first.groups!.topics.every((t) => !t.name.startsWith('Late'))).toBe(true);
    // The call goes on in the background; its names go on the cached grouping.
    namer.answer('Late');
    await settle();
    const second = await mapWith(namer.names, { namingWaitMs: 100 });
    expect(second.groups!.named).toBe('model');
    expect(second.groups!.topics[0].name).toBe('Late 1');
    expect(second.groups!.groupedAt).toBe(first.groups!.groupedAt);
    expect(namer.calls()).toBe(1);
  });

  it('asks a namer that failed again, but not on every request', async () => {
    let calls = 0;
    const failing: Namer = async () => { calls++; throw new Error('provider down'); };
    const t = Date.parse('2026-11-16T10:00:00Z');
    expect((await mapWith(failing, { now: new Date(t) })).groups!.named).toBe('keywords');
    await mapWith(failing, { now: new Date(t + 60_000) });
    expect(calls).toBe(1);
    await mapWith(failing, { now: new Date(t + NAMING_RETRY_MS) });
    expect(calls).toBe(2);
    const later = await mapWith(async (plan) => ({ topics: plan.map((_, i) => `Back ${i + 1}`), subs: plan.map((g) => g.subs.map(() => '')) }),
      { now: new Date(t + 2 * NAMING_RETRY_MS) });
    expect(later.groups!.topics[0].name).toBe('Back 1');
  });

  it('keeps nothing of a permanently deleted memory: not its id, not a name its words gave', async () => {
    // The namer names each topic after the first memory it is shown.
    const after: Namer = async (plan) => ({ topics: plan.map((g) => `About ${g.samples[0]}`), subs: plan.map((g) => g.subs.map(() => '')) });
    const first = await mapWith(after);
    const name = first.groups!.topics[0].name;
    const all = (await buildMemoryMap(ctx, { limit: 500 })).memories;
    const gone = all.find((m) => name === `About ${m.title}`)!;
    expect(gone).toBeDefined();
    expect(stored()).toContain(gone.id);
    expect(stored()).toContain(name);
    await retireMemory(ctx, gone.id);
    const rid = (await buildMemoryMap(ctx)).retired.find((r) => r.memoryId === gone.id)!.id;
    await purgeRetired(ctx, rid);
    expect(stored()).toBeNull();
    await mapWith(after);
    expect(stored()).not.toBeNull();
    expect(stored()).not.toContain(gone.id);
    expect(stored()).not.toContain(name);
  });

  it('does not write back names asked for before a permanent deletion', async () => {
    const now = new Date('2026-11-16T10:00:00Z');
    const before = held();
    await mapWith(before.names, { now, namingWaitMs: 50 });
    const all = (await buildMemoryMap(ctx, { limit: 500 })).memories;
    await retireMemory(ctx, all[0].id);
    const rid = (await buildMemoryMap(ctx)).retired.find((r) => r.memoryId === all[0].id)!.id;
    await purgeRetired(ctx, rid);
    // Grouped again at the same moment, so only the cache's epoch tells the two groupings apart.
    const fresh = held();
    const pending = mapWith(fresh.names, { now, namingWaitMs: 10_000 });
    await until(() => fresh.calls() > 0);
    expect(fresh.calls()).toBe(1);
    fresh.answer('Fresh');
    expect((await pending).groups!.topics[0].name).toBe('Fresh 1');
    before.answer('Stale');
    await settle();
    expect(stored()).toContain('Fresh 1');
    expect(stored()).not.toContain('Stale');
  });

  it('does not give a regrouping the names asked for the grouping before it', async () => {
    const t = Date.parse('2026-11-16T10:00:00Z');
    const old = held();
    await mapWith(old.names, { now: new Date(t), namingWaitMs: 50 });
    // Regrouped after the cache's age limit: the epoch is unchanged, only the grouping differs.
    const fresh = held();
    const pending = mapWith(fresh.names, { now: new Date(t + REGROUP_AFTER_MS + 1000), namingWaitMs: 10_000 });
    await until(() => fresh.calls() > 0);
    expect(fresh.calls()).toBe(1);
    fresh.answer('Fresh');
    expect((await pending).groups!.topics[0].name).toBe('Fresh 1');
    old.answer('Stale');
    await settle();
    expect(stored()).toContain('Fresh 1');
    expect(stored()).not.toContain('Stale');
  });

  it('groups again from scratch once much has changed', async () => {
    await map();
    writeDay('2026-10-05', Array.from({ length: 30 }, (_, k) => `seeds for the garden batch #${300 + k}`));
    await indexVault(db, vault, {});
    const after = await map();
    expect(namerCalls).toBe(2);
    expect(Object.keys(after.groups!.of).length).toBe(150);
  });

  it('groups again when the cache is dropped or the embedding space changes', async () => {
    await map();
    clearTopicCache(db);
    await map();
    expect(namerCalls).toBe(2);
    source = { ...source, space: 'another-space' };
    await map();
    expect(namerCalls).toBe(3);
  });

  it('has no topics without stored vectors', async () => {
    source = { space: null, vectorOf: () => null };
    const reply = await map();
    expect(reply.groups).toBeNull();
  });
});
