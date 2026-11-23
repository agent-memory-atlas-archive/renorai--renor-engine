/**
 * get_context puts this project's memories first and marks another project's (RENOR_CONTEXT_SCOPE_FIRST, on by default;
 * `0`, `false`, `no` or `off` gives the reply it always was).
 *
 * The project is the scope the read passed, else the one the connection records (x-renor-scope, written by `renor connect`).
 * With it, a note under `Memory/Scopes/<this project>/` or outside any project scope keeps its order and comes first; a note
 * under another project's `Memory/Scopes/<other>/` follows them, tagged `otherProject: true` with `savedIn: <other>`.
 * Nothing is dropped. With no project known, nothing changes.
 */
export const CONTEXT_SCOPE_FIRST_FLAG = 'RENOR_CONTEXT_SCOPE_FIRST';

export function contextScopeFirstEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env[CONTEXT_SCOPE_FIRST_FLAG] ?? '').trim().toLowerCase();
  return !(raw === '0' || raw === 'false' || raw === 'no' || raw === 'off');
}

export interface ScopeFirstMemory { notePath: string; otherProject?: true; savedIn?: string }

const SCOPE_DIR = /(?:^|\/)Memory\/Scopes\/([^/]+)(?:\/|$)/;

/** The project slug of a connection or read scope (`project:x`, `scope:x`, or bare `x`); null for none or `global`. */
export function projectSlugOf(raw: string | undefined | null): string | null {
  const s = (raw ?? '').trim().toLowerCase().replace(/^(?:scope|project):/, '');
  return s === '' || s === 'global' ? null : s;
}

/** The project a note's path puts it in, or null for a note outside every project scope. */
export function pathProject(notePath: string): string | null {
  return SCOPE_DIR.exec(notePath.replace(/\\/g, '/'))?.[1]?.toLowerCase() ?? null;
}

/** `memories` with this project's (and unscoped) first, in their order, then other projects' tagged. Idempotent. */
export function scopeFirstMemories<T extends ScopeFirstMemory>(memories: readonly T[], project: string | null, savedScopeOf?: (memory: T) => string | null): T[] {
  if (project === null) return [...memories];
  const own: T[] = [];
  const other: T[] = [];
  for (const memory of memories) {
    // A note outside `Memory/Scopes/` (a ledger-backed fact) falls back to the scope its event was saved in, when the caller knows it.
    const at = pathProject(memory.notePath) ?? savedScopeOf?.(memory) ?? null;
    if (at === null || at === project) own.push(memory);
    else other.push(memory.otherProject ? memory : { ...memory, otherProject: true, savedIn: at });
  }
  return other.length === 0 ? [...memories] : [...own, ...other];
}
