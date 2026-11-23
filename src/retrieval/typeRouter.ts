/** What a hit gains when its note's record kind is the kind the question needs. */
export const TYPE_ROUTER_BOOST = 0.1;

export type MemoryType = 'profile' | 'event' | 'source';

/**
 * RENOR_RETRIEVE_TYPE_ROUTER (default off, a research lever, lever `query-memory-type-routing`): `1`, `on`, `true` or
 * `yes` ranks notes of the record kind the question needs (profile, event, source) a little higher. Unset or anything
 * else: the rank is unchanged.
 */
export function typeRouterEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return ['1', 'on', 'true', 'yes'].includes((env.RENOR_RETRIEVE_TYPE_ROUTER ?? '').trim().toLowerCase());
}

const EVENT = /\b(when|what\s+(?:day|date|time|year)|last\s+(?:week|month|year|time)|yesterday|ago|happened|did\s+we|did\s+i)\b/i;
const PROFILE = /\b(prefer(?:s|ence|ences)?|favou?rite|my\s+(?:name|role|job|timezone|style)|how\s+do\s+i\s+like|i\s+like|i\s+usually|do\s+i\s+(?:like|use|prefer))\b/i;
const SOURCE = /\b(quote|verbatim|exact(?:ly)?|according\s+to|in\s+the\s+(?:doc|document|file|readme)|says?)\b/i;

/** The record kind a question needs, by plain rules over its words; null when none stands out. Deterministic, no model. */
export function routeQueryType(query: string): MemoryType | null {
  if (EVENT.test(query)) return 'event';
  if (PROFILE.test(query)) return 'profile';
  if (SOURCE.test(query)) return 'source';
  return null;
}

const KIND_OF: Record<string, MemoryType> = {
  profile: 'profile', preference: 'profile', preferences: 'profile', person: 'profile',
  event: 'event', session: 'event', meeting: 'event', journal: 'event', conversation: 'event',
  source: 'source', document: 'source', doc: 'source', reference: 'source',
};

/** The record kind a note declares (frontmatter `kind`, else `type`), or null. */
export function noteMemoryType(frontmatterJson: string | undefined): MemoryType | null {
  if (!frontmatterJson) return null;
  try {
    const fm = JSON.parse(frontmatterJson) as Record<string, unknown>;
    for (const key of ['kind', 'type']) {
      const v = fm[key];
      if (typeof v === 'string' && KIND_OF[v.toLowerCase()]) return KIND_OF[v.toLowerCase()]!;
    }
  } catch { /* not JSON: no declared kind */ }
  return null;
}
