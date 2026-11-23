/**
 * Research lever RENOR_CAPTURE_EVOLVE_NEIGHBORS (default off), after A-Mem (arXiv 2502.12110): when a capture saves new
 * observations, one extra model call looks at the closest existing notes and says which of them the new facts make stale.
 * Each such note gets a NEW dated note that restates it ("Update: ..."). Old notes are never edited, so the undo is the normal
 * one: retire the new note. Off, none of this runs and capture is byte-identical.
 */
import { anthropicRequestBody, describeUpstreamError } from './captureModel.js';

export const EVOLVE_MAX_NEIGHBORS = 6;
export const EVOLVE_MAX_UPDATES = 3;
export const EVOLVE_MAX_OUTPUT_TOKENS = 1024;
const EVOLVE_NOTE_CHARS = 400;

export const EVOLVE_SYSTEM_PROMPT = `You keep a user's memory notes current. You get NEW facts and a numbered list of EXISTING notes. Return ONLY JSON {"updates":[{"note":<number of the existing note>,"text":"..."}]}. Include an update only when a new fact contradicts, replaces or materially changes an existing note; its text restates that note as it is true now, under 280 characters, in plain third person, with absolute dates. Return {"updates":[]} when nothing is stale. Never include secrets, code or tool output.`;

export function evolveNeighborsEnabled(env: NodeJS.ProcessEnv): boolean {
  return env.RENOR_CAPTURE_EVOLVE_NEIGHBORS === '1';
}

export function evolveUserContent(newFacts: readonly string[], neighbors: readonly string[]): string {
  return JSON.stringify({
    new: newFacts.map(t => t.slice(0, 280)),
    existing: neighbors.slice(0, EVOLVE_MAX_NEIGHBORS).map((text, i) => ({ note: i + 1, text: text.slice(0, EVOLVE_NOTE_CHARS) })),
  });
}

export function parseEvolveReply(raw: string, neighborCount: number): string[] | null {
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(raw.slice(start, end + 1)); } catch { return null; }
  const updates = (parsed as { updates?: unknown })?.updates;
  if (!Array.isArray(updates)) return null;
  const out: string[] = [];
  const seen = new Set<number>();
  for (const u of updates) {
    const note = (u as { note?: unknown })?.note;
    const text = (u as { text?: unknown })?.text;
    if (typeof note !== 'number' || !Number.isInteger(note) || note < 1 || note > neighborCount || seen.has(note)) continue;
    if (typeof text !== 'string') continue;
    const t = text.trim();
    if (!t || t.length > 280) continue;
    seen.add(note);
    out.push(`Update: ${t}`);
    if (out.length >= EVOLVE_MAX_UPDATES) break;
  }
  return out;
}

/** The most the call can cost, from its request bytes (one token per byte at the dearest input price) and its output cap. */
export function evolveMaxUsd(content: string, price: { input: number; output: number }): number {
  const bytes = Buffer.byteLength(EVOLVE_SYSTEM_PROMPT, 'utf8') + Buffer.byteLength(content, 'utf8') + 2048;
  return (bytes * price.input * 1.25 + EVOLVE_MAX_OUTPUT_TOKENS * price.output) / 1e6;
}

export type EvolveResult = { updates: string[]; inTokens: number | null; outTokens: number | null };

/** One Anthropic call. Null on any failure: the capture then goes on without the lever. */
export async function callEvolve(
  content: string, neighborCount: number, config: { model: string; key: string }, fetchImpl: typeof fetch = fetch,
): Promise<EvolveResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetchImpl('https://api.anthropic.com/v1/messages', {
      method: 'POST', redirect: 'error', signal: controller.signal,
      headers: { 'content-type': 'application/json', 'x-api-key': config.key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(anthropicRequestBody(config.model, {
        max_tokens: EVOLVE_MAX_OUTPUT_TOKENS,
        system: [{ type: 'text', text: EVOLVE_SYSTEM_PROMPT }],
        messages: [{ role: 'user', content }],
      })),
    });
    if (!response.ok) { await describeUpstreamError(response); return null; }
    const body = await response.json() as { stop_reason?: unknown; content?: Array<{ type?: string; text?: string }>; usage?: Record<string, unknown> };
    if (body.stop_reason !== 'end_turn' && body.stop_reason !== 'stop_sequence') return null;
    const raw = (Array.isArray(body.content) ? body.content : []).filter(x => x?.type === 'text').map(x => x.text ?? '').join('');
    const updates = parseEvolveReply(raw, neighborCount);
    if (!updates) return null;
    const n = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null);
    return { updates, inTokens: n(body.usage?.input_tokens), outTokens: n(body.usage?.output_tokens) };
  } catch { return null; } finally { clearTimeout(timer); }
}
