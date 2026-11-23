import fs from 'node:fs';
import path from 'node:path';

/**
 * Citation-locked answers (RENOR_ANSWER_CITATION_LOCK, issue #2075, off by default). A get_context memory the reader cannot
 * open with read_memory is a claim it cannot cite, so with the lock on the reply keeps only memories whose note exists in the
 * memory folder (or is a ledger record) and says "Nothing citable" when nothing is left to cite, so the agent abstains
 * instead of answering from a stale hit. No model call; one stat per memory. Unset leaves every served byte identical.
 */
export const ANSWER_CITATION_LOCK_FLAG = 'RENOR_ANSWER_CITATION_LOCK';

export const NOTHING_CITABLE = 'Nothing citable: no saved note this request matched can be opened. Say you have nothing saved on it.';

/** On only for 1, true, yes or on. */
export function citationLockEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env[ANSWER_CITATION_LOCK_FLAG] ?? '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

/** The reply with its un-openable memories removed; a reply left with no memory and no fact gets NOTHING_CITABLE in `notice`. */
export function applyCitationLock<R extends Record<string, unknown>>(reply: R, memoryDir: string, isLedger: (notePath: string) => boolean): R {
  const memories = reply.memories;
  if (!Array.isArray(memories)) return reply;
  const root = path.resolve(memoryDir);
  const openable = (m: { notePath?: unknown }): boolean => {
    if (typeof m?.notePath !== 'string' || m.notePath === '') return false;
    if (isLedger(m.notePath)) return true;
    const full = path.resolve(root, m.notePath);
    return (full === root || full.startsWith(root + path.sep)) && fs.existsSync(full);
  };
  const kept = memories.filter(openable);
  if (kept.length === memories.length) return reply;
  const facts = Array.isArray(reply.facts) ? reply.facts : [];
  const out: Record<string, unknown> = { ...reply, memories: kept };
  if (kept.length === 0 && facts.length === 0) out.notice = [reply.notice, NOTHING_CITABLE].filter(Boolean).join(' ');
  return out as R;
}
