/**
 * Research lever RENOR_OBSERVATION_NOTES (default off), after Mastra observational memory: when a capture saves new
 * observations, one extra model call (observer + reflector in one) folds them, and the earlier "Notes:" digests it is shown,
 * into ONE compact running-notes digest. The digest is saved as ONE new dated note ("Notes: ..."); the raw observations stay
 * saved, so every digest line can be checked against the raw records. Old notes are never edited: the undo is retire_memory on
 * the new note. Off, none of this runs and capture is byte-identical.
 */
import { anthropicRequestBody, describeUpstreamError } from './captureModel.js';

export const NOTES_MAX_PRIOR = 3;
export const NOTES_MAX_OUTPUT_TOKENS = 512;
export const NOTES_PREFIX = 'Notes:';
const NOTES_PRIOR_CHARS = 600;
const NOTES_MAX_CHARS = 700;

export const NOTES_SYSTEM_PROMPT = `You keep running notes for a user's memory. You get NEW facts and the PRIOR notes digests, if any. Return ONLY JSON {"notes":["..."]}. notes: 1 to 6 short plain third-person lines that together say what is now true and what matters, merging the prior digests with the new facts, dropping repeats and anything the new facts replace. Each line under 140 characters. Never include secrets, code or tool output.`;

export function observationNotesEnabled(env: NodeJS.ProcessEnv): boolean {
  return env.RENOR_OBSERVATION_NOTES === '1';
}

/** The prior digests among the neighbour texts, newest-looking first as given. */
export function priorDigests(neighbors: readonly string[]): string[] {
  return neighbors.filter(t => t.startsWith(NOTES_PREFIX)).slice(0, NOTES_MAX_PRIOR);
}

export function notesUserContent(newFacts: readonly string[], prior: readonly string[]): string {
  return JSON.stringify({
    new: newFacts.map(t => t.slice(0, 280)),
    prior: prior.slice(0, NOTES_MAX_PRIOR).map(t => t.slice(0, NOTES_PRIOR_CHARS)),
  });
}

/** The note text to save, or null when the reply is unusable. */
export function parseNotesReply(raw: string): string | null {
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  let parsed: { notes?: unknown };
  try { parsed = JSON.parse(raw.slice(start, end + 1)); } catch { return null; }
  const lines = (Array.isArray(parsed.notes) ? parsed.notes : [])
    .filter((l): l is string => typeof l === 'string' && l.trim().length > 0 && l.length <= 140)
    .map(l => l.replace(/\s+/g, ' ').trim()).slice(0, 6);
  if (lines.length === 0) return null;
  const note = `${NOTES_PREFIX} ${lines.join(' ')}`;
  return note.length > NOTES_MAX_CHARS ? null : note;
}

/** The most the call can cost, from its request bytes (one token per byte at the dearest input price) and its output cap. */
export function notesMaxUsd(content: string, price: { input: number; output: number }): number {
  const bytes = Buffer.byteLength(NOTES_SYSTEM_PROMPT, 'utf8') + Buffer.byteLength(content, 'utf8') + 2048;
  return (bytes * price.input * 1.25 + NOTES_MAX_OUTPUT_TOKENS * price.output) / 1e6;
}

export type NotesResult = { note: string; inTokens: number | null; outTokens: number | null };

/** One Anthropic call. Null on any failure: the capture then goes on without the lever. */
export async function callNotes(
  content: string, config: { model: string; key: string }, fetchImpl: typeof fetch = fetch,
): Promise<NotesResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetchImpl('https://api.anthropic.com/v1/messages', {
      method: 'POST', redirect: 'error', signal: controller.signal,
      headers: { 'content-type': 'application/json', 'x-api-key': config.key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(anthropicRequestBody(config.model, {
        max_tokens: NOTES_MAX_OUTPUT_TOKENS,
        system: [{ type: 'text', text: NOTES_SYSTEM_PROMPT }],
        messages: [{ role: 'user', content }],
      })),
    });
    if (!response.ok) { await describeUpstreamError(response); return null; }
    const body = await response.json() as { stop_reason?: unknown; content?: Array<{ type?: string; text?: string }>; usage?: Record<string, unknown> };
    if (body.stop_reason !== 'end_turn' && body.stop_reason !== 'stop_sequence') return null;
    const raw = (Array.isArray(body.content) ? body.content : []).filter(x => x?.type === 'text').map(x => x.text ?? '').join('');
    const note = parseNotesReply(raw);
    if (!note) return null;
    const n = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null);
    return { note, inTokens: n(body.usage?.input_tokens), outTokens: n(body.usage?.output_tokens) };
  } catch { return null; } finally { clearTimeout(timer); }
}
