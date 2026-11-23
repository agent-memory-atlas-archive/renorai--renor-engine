/**
 * Research lever RENOR_CAPTURE_NOTE_LINKS (default off), after A-Mem (arXiv 2502.12110): when a capture saves new
 * observations, one extra model call writes keywords and a one-line context for them and picks which of the closest existing
 * notes they relate to. The result is saved as ONE new dated note ("Links: ..."). Old notes are never edited, so the undo is
 * the normal one: retire the new note. Off, none of this runs and capture is byte-identical.
 */
import { anthropicRequestBody, describeUpstreamError } from './captureModel.js';

export const LINKS_MAX_NEIGHBORS = 6;
export const LINKS_MAX_OUTPUT_TOKENS = 512;
const LINKS_NOTE_CHARS = 400;
const LINKS_QUOTE_CHARS = 90;

export const LINKS_SYSTEM_PROMPT = `You index a user's memory notes. You get NEW facts and a numbered list of EXISTING notes. Return ONLY JSON {"keywords":["..."],"context":"...","related":[<numbers of existing notes>]}. keywords: 2 to 6 short lowercase words or phrases a later question might use. context: one plain third-person sentence under 200 characters saying what the new facts are about. related: numbers of existing notes about the same person, project or topic as the new facts; [] when none. Never include secrets, code or tool output.`;

export function noteLinksEnabled(env: NodeJS.ProcessEnv): boolean {
  return env.RENOR_CAPTURE_NOTE_LINKS === '1';
}

export function linksUserContent(newFacts: readonly string[], neighbors: readonly string[]): string {
  return JSON.stringify({
    new: newFacts.map(t => t.slice(0, 280)),
    existing: neighbors.slice(0, LINKS_MAX_NEIGHBORS).map((text, i) => ({ note: i + 1, text: text.slice(0, LINKS_NOTE_CHARS) })),
  });
}

/** The note text to save, or null when the reply is unusable. `neighbors` are the numbered notes the model saw. */
export function parseLinksReply(raw: string, neighbors: readonly string[]): string | null {
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  let parsed: { keywords?: unknown; context?: unknown; related?: unknown };
  try { parsed = JSON.parse(raw.slice(start, end + 1)); } catch { return null; }
  const context = typeof parsed.context === 'string' ? parsed.context.trim() : '';
  if (!context || context.length > 200) return null;
  const keywords = (Array.isArray(parsed.keywords) ? parsed.keywords : [])
    .filter((k): k is string => typeof k === 'string' && k.trim().length > 0 && k.length <= 40).map(k => k.trim()).slice(0, 6);
  const related: string[] = [];
  const seen = new Set<number>();
  for (const n of Array.isArray(parsed.related) ? parsed.related : []) {
    if (typeof n !== 'number' || !Number.isInteger(n) || n < 1 || n > neighbors.length || seen.has(n)) continue;
    seen.add(n);
    related.push(`"${neighbors[n - 1].replace(/\s+/g, ' ').trim().slice(0, LINKS_QUOTE_CHARS)}"`);
    if (related.length >= 3) break;
  }
  if (keywords.length === 0 && related.length === 0) return null;
  const parts = [`Links: ${context}`];
  if (keywords.length) parts.push(`Keywords: ${keywords.join(', ')}.`);
  if (related.length) parts.push(`Related notes: ${related.join('; ')}.`);
  return parts.join(' ');
}

/** The most the call can cost, from its request bytes (one token per byte at the dearest input price) and its output cap. */
export function linksMaxUsd(content: string, price: { input: number; output: number }): number {
  const bytes = Buffer.byteLength(LINKS_SYSTEM_PROMPT, 'utf8') + Buffer.byteLength(content, 'utf8') + 2048;
  return (bytes * price.input * 1.25 + LINKS_MAX_OUTPUT_TOKENS * price.output) / 1e6;
}

export type LinksResult = { note: string; inTokens: number | null; outTokens: number | null };

/** One Anthropic call. Null on any failure: the capture then goes on without the lever. */
export async function callLinks(
  content: string, neighbors: readonly string[], config: { model: string; key: string }, fetchImpl: typeof fetch = fetch,
): Promise<LinksResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetchImpl('https://api.anthropic.com/v1/messages', {
      method: 'POST', redirect: 'error', signal: controller.signal,
      headers: { 'content-type': 'application/json', 'x-api-key': config.key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(anthropicRequestBody(config.model, {
        max_tokens: LINKS_MAX_OUTPUT_TOKENS,
        system: [{ type: 'text', text: LINKS_SYSTEM_PROMPT }],
        messages: [{ role: 'user', content }],
      })),
    });
    if (!response.ok) { await describeUpstreamError(response); return null; }
    const body = await response.json() as { stop_reason?: unknown; content?: Array<{ type?: string; text?: string }>; usage?: Record<string, unknown> };
    if (body.stop_reason !== 'end_turn' && body.stop_reason !== 'stop_sequence') return null;
    const raw = (Array.isArray(body.content) ? body.content : []).filter(x => x?.type === 'text').map(x => x.text ?? '').join('');
    const note = parseLinksReply(raw, neighbors);
    if (!note) return null;
    const n = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null);
    return { note, inTokens: n(body.usage?.input_tokens), outTokens: n(body.usage?.output_tokens) };
  } catch { return null; } finally { clearTimeout(timer); }
}
