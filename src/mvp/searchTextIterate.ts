import { expansionMatch, expansionTerms } from './contextExpand.js';

/**
 * search_text's second look (RENOR_RECALL_AGENTIC_GREP, issue #2072). An agent that greps a plain file reads what it found and
 * greps again with the file's own words; a memory saved in other words than the question is reached that way (multi-hop).
 * One extra keyword search per call, no model call: the question plus the distinctive words of the best hits, its hits placed
 * after every direct hit and the page never longer than top_k. Unset leaves every served byte identical.
 */
export const RECALL_AGENTIC_GREP_FLAG = 'RENOR_RECALL_AGENTIC_GREP';

/** On only for 1, true, yes or on. */
export function recallAgenticGrepEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env[RECALL_AGENTIC_GREP_FLAG] ?? '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

/** The FTS expression and the query words of the second search for these hits, or null when they hold no new vocabulary. */
export function secondLook(query: string, hits: ReadonlyArray<{ text: string }>): { match: string; query: string } | null {
  const terms = expansionTerms(query, hits.map(hit => hit.text));
  return terms.length === 0 ? null : { match: expansionMatch(query, terms), query: [query, ...terms].join(' ') };
}

/** The direct hits, then the extra ones that are not already there, cut to topK. */
export function appendNew<T extends { notePath: string; headingPath?: string; text: string }>(direct: T[], extra: T[], topK: number): T[] {
  const key = (hit: T) => `${hit.notePath}\u0000${hit.headingPath ?? ''}\u0000${hit.text}`;
  const seen = new Set(direct.map(key));
  const out = [...direct];
  for (const hit of extra) {
    if (out.length >= topK) break;
    if (!seen.has(key(hit))) { seen.add(key(hit)); out.push(hit); }
  }
  return out;
}
