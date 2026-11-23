import { FTS_STOP_WORDS } from '../retrieval/keyword';

/**
 * get_context's feedback expansion (RENOR_CONTEXT_EXPAND, issue #2004). A memory saved in other words than the question is
 * found by neither search. The words of the best few matches the question did find are the memory's own vocabulary, so one
 * more keyword search with the question plus the distinctive words of those matches can reach a record that shares no word
 * with the question. No model call, no new provider, one extra keyword search per call, and its hits follow every direct hit.
 */
export const CONTEXT_EXPAND_FLAG = 'RENOR_CONTEXT_EXPAND';

/** On only for 1, true, yes or on; unset leaves every served byte identical. */
export function contextExpandEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env[CONTEXT_EXPAND_FLAG] ?? '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

/** The best matches read for terms, and the most terms added to the question. */
export const EXPAND_SOURCES = 3;
export const EXPAND_TERMS = 8;
const MIN_LENGTH = 5;

const tokens = (text: string): string[] => text.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);

/**
 * The distinctive words of the top matches that the question does not use: at least five letters, no stop word, no
 * number. A word is the more distinctive the fewer of the matches' own words it shares a count with (a word in every
 * match is the topic, not a rare detail) and the longer it is; ties break alphabetically, so the order is the same on every call.
 */
export function expansionTerms(query: string, texts: ReadonlyArray<string>, limit: number = EXPAND_TERMS): string[] {
  const asked = new Set(tokens(query).filter(w => !FTS_STOP_WORDS.has(w)));
  const sets = texts.map(text => new Set(tokens(text)));
  // The matches read are the ones that share the question's rarest words (a word few of the matches hold counts most): the
  // top three by that overlap, not simply the first three, which can be matches of the question's common words.
  const df = new Map<string, number>();
  for (const set of sets) for (const w of asked) if (set.has(w)) df.set(w, (df.get(w) ?? 0) + 1);
  const overlap = (set: Set<string>): number => { let n = 0; for (const w of asked) if (set.has(w)) n += Math.log(1 + sets.length / df.get(w)!); return n; };
  const top = sets.map((set, i) => ({ set, i, o: overlap(set) })).sort((a, b) => b.o - a.o || a.i - b.i).slice(0, EXPAND_SOURCES).filter(x => x.o > 0);
  const inMatches = new Map<string, number>();
  for (const { set } of top) for (const word of set) {
    if (word.length < MIN_LENGTH || tokens(query).includes(word) || FTS_STOP_WORDS.has(word) || /^\p{N}+$/u.test(word)) continue;
    inMatches.set(word, (inMatches.get(word) ?? 0) + 1);
  }
  const weight = (word: string): number => word.length / (1 + inMatches.get(word)! * 0.5);
  return [...inMatches.keys()].sort((a, b) => weight(b) - weight(a) || (a < b ? -1 : 1)).slice(0, Math.max(0, limit));
}

/** The FTS expression of the one extra search: the question's words and the added ones, or an OR over the words alone. */
export function expansionMatch(query: string, terms: ReadonlyArray<string>): string {
  const all = [...new Set([...tokens(query).filter(w => !FTS_STOP_WORDS.has(w)), ...terms])];
  return all.map(term => `"${term.replace(/"/g, '""')}"`).join(' OR ');
}

const EXPANDED = Symbol('contextExpand');

/**
 * The matches the extra search added are marked on the item itself with a symbol key: object spreads (the copies made
 * before the budget) keep it, JSON.stringify never serves it. They keep reason `fts` (so a duplicate of a direct hit still
 * merges into it), but the budget order places them after every direct match, with or without RENOR_CONTEXT_RANK_FUSION.
 */
export function markExpansion<T extends object>(memory: T): T {
  (memory as Record<symbol, unknown>)[EXPANDED] = true;
  return memory;
}

export function isExpansion(memory: object): boolean {
  return (memory as Record<symbol, unknown>)[EXPANDED] === true;
}
