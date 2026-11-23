import { encodeTokens } from '../indexer/tokenizer.js';
import { observeEnabled } from './observations.js';

/**
 * get_context with fewer observed records (RENOR_OBSERVE_COMPACT, on by default; `0` restores the earlier reply).
 *
 * With RENOR_OBSERVE on, every stored prompt and tool record that matches the query is listed as its own memory. At 500
 * stored prompts that made the reply more than twice the size of the one without them (14,368 tokens against 6,585).
 * Three cuts, applied to observed records only, never to a saved memory:
 *  1. an observed record whose words a saved memory already holds is dropped (the saved memory stays);
 *  2. the observed records of one session become one line: the best-matching one, cut to a sentence, with how many
 *     records the session had; its notePath is the best record's, so read_memory expands it;
 *  3. when saved memories are listed, observed lines together take at most a third of the memories' tokens.
 * A reply with no observed record is returned as it was (same array, untouched).
 */
export const OBSERVE_COMPACT_FLAG = 'RENOR_OBSERVE_COMPACT';
export const OBSERVED_SHARE = 1 / 3;
export const OBSERVED_LINE_CHARS = 200;

export function observeCompactEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return !/^(0|off|false|no)$/i.test(env.RENOR_OBSERVE_COMPACT?.trim() ?? '');
}

interface Item { notePath: string; text: string; score?: number; source?: string; session_date?: string }

const HEADER = /^\[Observation · [^\]]*\]\n?/;
const words = (text: string): string => text.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
const isObserved = (item: Item): boolean => item.source === 'observation';
const sessionOf = (item: Item): string => item.notePath.split('/').slice(0, 2).join('/');
const tokens = (item: Item): number => encodeTokens(JSON.stringify(item));

/** The first sentence of a record, at most OBSERVED_LINE_CHARS characters. */
function firstSentence(body: string): string {
  const flat = body.replace(/\s+/g, ' ').trim();
  const end = flat.search(/[.!?](\s|$)/);
  const sentence = end >= 0 ? flat.slice(0, end + 1) : flat;
  return sentence.length <= OBSERVED_LINE_CHARS ? sentence : sentence.slice(0, OBSERVED_LINE_CHARS - 1).trimEnd() + '…';
}

export function compactObservedMemories<T extends Item>(memories: T[], env: NodeJS.ProcessEnv = process.env): T[] {
  if (!observeEnabled(env) || !observeCompactEnabled(env) || !memories.some(isObserved)) return memories;
  const saved = memories.filter(item => !isObserved(item));
  const savedWords = saved.map(item => words(item.text));

  const sessions = new Map<string, { best: T; count: number; position: number }>();
  memories.forEach((item, position) => {
    if (!isObserved(item)) return;
    const body = words(item.text.replace(HEADER, ''));
    if (body.length >= 20 && savedWords.some(held => held.includes(body))) return;
    const key = sessionOf(item);
    const seen = sessions.get(key);
    if (!seen) sessions.set(key, { best: item, count: 1, position });
    else {
      seen.count += 1;
      if ((item.score ?? 0) > (seen.best.score ?? 0)) seen.best = item;
    }
  });

  const lines = new Map<number, T>();
  for (const { best, count, position } of sessions.values()) {
    const header = best.text.match(HEADER)?.[0].trim() ?? '[Observation]';
    const more = count > 1 ? ` (${count} records this session)` : '';
    lines.set(position, { ...best, text: `${header.slice(0, -1)}${more}]\n${firstSentence(best.text.replace(HEADER, ''))}` });
  }

  let observedTokens = [...lines.values()].reduce((sum, item) => sum + tokens(item), 0);
  if (saved.length > 0) {
    const cap = (saved.reduce((sum, item) => sum + tokens(item), 0) * OBSERVED_SHARE) / (1 - OBSERVED_SHARE);
    const worstFirst = [...lines.entries()].sort((a, b) => (a[1].score ?? 0) - (b[1].score ?? 0));
    for (const [position, item] of worstFirst) {
      if (observedTokens <= cap) break;
      lines.delete(position);
      observedTokens -= tokens(item);
    }
  }

  return memories.flatMap((item, position) => (isObserved(item) ? (lines.has(position) ? [lines.get(position)!] : []) : [item]));
}
