// ---------------------------------------------------------------------------
// Topic names from Gemini on Vertex, for a workspace whose embeddings are on Vertex.
//
// The memory map names its topics with one model call per full grouping (topics.ts chatNamer): a few sample lines
// from each topic and subtopic go out, about 10k tokens, and a short JSON of names comes back. A workspace that
// embeds with Vertex already sends its memories' text there, so the names are asked of the same project and
// service-account key: no other company sees the samples. Flash-Lite is the model: the task is short labels, and a
// grouping costs well under a cent. A grouping is redone at most every two weeks or after a 15% change
// (topicStore.ts), so a person costs about a cent a month at most.
//
// As of 2026-11 the model is not served from the embeddings region, so the call goes to Vertex's
// United States multi-region (location `us`), which keeps the samples in the United States as the privacy policy
// says. The global location would let Google serve it from any region.
//
// The call goes to Vertex's OpenAI-compatible chat endpoint, which takes the request chatNamer already builds.
// ---------------------------------------------------------------------------

import type { NamingChat } from './topics.js';

/** The model topics are named with. */
export const TOPIC_NAMING_MODEL = 'google/gemini-3.1-flash-lite';
/** The Vertex location that serves it: the United States multi-region. */
export const TOPIC_NAMING_LOCATION = 'us';

/**
 * A bound on the call itself. A dashboard request waits only a few seconds for it (topicStore.ts, NAMING_WAIT_MS) and
 * answers with keyword names; the call goes on in the background up to this long, and its names reach the next request.
 */
const NAMING_TIMEOUT_MS = 60_000;

export interface VertexNamingOptions {
  project: string;
  /** Unset: TOPIC_NAMING_LOCATION. */
  location?: string;
  /** A bearer token for the project (the embedding provider's, vertex.ts bearerToken). */
  token(signal?: AbortSignal): Promise<string>;
  /** Where the endpoint is served from. Unset: Google's, from the location. A test points it at a local stub. */
  baseUrl?: string;
  request?: typeof fetch;
  timeoutMs?: number;
}

function endpoint(options: VertexNamingOptions): string {
  const project = options.project;
  const location = options.location ?? TOPIC_NAMING_LOCATION;
  if (!/^[a-z0-9-]+$/.test(project) || !/^[a-z0-9-]+$/.test(location)) throw new Error('Vertex project and location must be plain ids');
  // A multi-region (us, eu) has its own host; a region is a prefix of the shared one.
  let base = location === 'us' || location === 'eu' ? `https://aiplatform.${location}.rep.googleapis.com` : `https://${location}-aiplatform.googleapis.com`;
  if (options.baseUrl !== undefined) {
    const url = new URL(options.baseUrl);
    const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]';
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) throw new Error('Vertex baseUrl must be https, or http on loopback');
    base = url.origin;
  }
  return `${base}/v1/projects/${project}/locations/${location}/endpoints/openapi/chat/completions`;
}

/** A NamingChat that asks Gemini on Vertex. It throws on a failed call; groupTopics then keeps keyword names. */
export function vertexNamingChat(options: VertexNamingOptions): NamingChat {
  const url = endpoint(options);
  return async (body) => {
    const signal = AbortSignal.timeout(options.timeoutMs ?? NAMING_TIMEOUT_MS);
    const token = await options.token(signal);
    const response = await (options.request ?? fetch)(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    });
    if (!response.ok) throw new Error(`Vertex topic naming failed: ${response.status}`);
    const data = await response.json() as { choices?: Array<{ message?: { content?: unknown } }> };
    const content = data.choices?.[0]?.message?.content;
    if (typeof content !== 'string') throw new Error('Vertex topic naming returned no text');
    return { content };
  };
}
