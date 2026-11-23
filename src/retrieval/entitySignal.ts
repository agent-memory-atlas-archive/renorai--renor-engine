import type Database from '../db/sqlite.js';

/** What a hit gains when its note holds an entity the question names. */
export const ENTITY_SIGNAL_BOOST = 0.15;

/**
 * RENOR_RETRIEVE_ENTITY_SIGNAL (default off, a research lever, lever `entity-signal-fusion`): `1`, `on`, `true` or `yes`
 * adds an entity-match signal to the vector and keyword rank. Unset or anything else: the rank is unchanged.
 */
export function entitySignalEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return ['1', 'on', 'true', 'yes'].includes((env.RENOR_RETRIEVE_ENTITY_SIGNAL ?? '').trim().toLowerCase());
}

/** Runs of one to three words of the question, longest first, at most `limit`: the names it might say. Deterministic, no model. */
export function entityCandidates(query: string, limit = 24): string[] {
  const words = query.match(/[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N}._-]*/gu) ?? [];
  const out: string[] = [];
  for (let n = 3; n >= 1; n--) {
    for (let i = 0; i + n <= words.length; i++) {
      const phrase = words.slice(i, i + n).join(' ');
      if (phrase.length >= 3 && !out.includes(phrase)) out.push(phrase);
      if (out.length >= limit) return out;
    }
  }
  return out;
}

/** The notes that hold an entity whose name or alias is exactly a run of the question (case ignored). */
export function entitySignalNotes(db: Database.Database, query: string): Set<string> {
  const notes = new Set<string>();
  const byName = db.prepare('SELECT source_note FROM entities WHERE canonical_name = ? COLLATE NOCASE');
  const byAlias = db.prepare(
    'SELECT entities.source_note FROM entities, json_each(entities.aliases_json) AS alias WHERE lower(alias.value) = lower(?)');
  for (const phrase of entityCandidates(query)) {
    for (const row of [...byName.all(phrase), ...byAlias.all(phrase)] as Array<{ source_note: string }>) notes.add(row.source_note);
  }
  return notes;
}
