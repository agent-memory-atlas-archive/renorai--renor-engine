/**
 * get_context lists a saved decision that answers the question first, marked as a decision (RENOR_CONTEXT_DECISION_FIRST,
 * off by default: the reply is then what it always was).
 *
 * A memory is a decision when its entry says so ("Decision: ...", "Decided ...", "We decided ..."). A decision that shares
 * enough of the question's words is listed before every other memory, in its own order, tagged `decision: true`, so one early
 * call tells the agent that the saved choice outranks what a repository suggests. Nothing is dropped or rewritten; the
 * memory's own date and reason stay in its text.
 */
export const CONTEXT_DECISION_FIRST_FLAG = 'RENOR_CONTEXT_DECISION_FIRST';

export function contextDecisionFirstEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env[CONTEXT_DECISION_FIRST_FLAG] ?? '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

export interface DecisionFirstMemory { text: string; decision?: true }

const DAILY_PREFIX = /^(\s*-\s*\[\d{2}:\d{2}(?::\d{2})?\]\s*(?:\([^)]*\)\s*)?)+/;
const DECISION = /^\W*(?:(?:we|i|the team)\s+)?(?:decision\s*:|decided\b|decide[sd]?\s+(?:to|on)\b)/i;
const STOP = new Set(['the', 'a', 'an', 'of', 'to', 'for', 'and', 'in', 'on', 'we', 'use', 'is', 'are', 'what', 'which', 'how', 'do', 'should', 'i', 'it', 'this', 'that', 'with']);

export function isDecision(text: string): boolean {
  return text.split('\n').some(line => DECISION.test(line.replace(DAILY_PREFIX, '')));
}

function words(text: string): Set<string> {
  return new Set(text.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(w => w.length > 2 && !STOP.has(w)));
}

/** `memories` with the decisions that share a word with the question first (tagged), the rest in order. Idempotent. */
export function decisionFirstMemories<T extends DecisionFirstMemory>(memories: readonly T[], query: string): T[] {
  const asked = words(query);
  if (asked.size === 0) return [...memories];
  const picked: T[] = [];
  const rest: T[] = [];
  for (const memory of memories) {
    const answers = isDecision(memory.text) && [...words(memory.text)].some(w => asked.has(w));
    (answers ? picked : rest).push(answers && !memory.decision ? { ...memory, decision: true } : memory);
  }
  return picked.length === 0 ? [...memories] : [...picked, ...rest];
}
