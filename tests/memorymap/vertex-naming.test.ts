import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { chatNamer } from '../../src/memorymap/topics';
import { TOPIC_NAMING_MODEL, vertexNamingChat } from '../../src/memorymap/vertexNaming';

interface Seen { url: string; auth: string | undefined; body: Record<string, unknown> }

let server: http.Server | null = null;

async function stub(reply: (seen: Seen) => { status: number; body: unknown }): Promise<{ base: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const s = { url: req.url ?? '', auth: req.headers.authorization, body: JSON.parse(raw) as Record<string, unknown> };
      seen.push(s);
      const r = reply(s);
      res.writeHead(r.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(r.body));
    });
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}

afterEach(async () => {
  if (server) await new Promise((resolve) => server!.close(resolve));
  server = null;
});

const groups = [
  { samples: ['merged PR 1611 after the gate went green'], subs: [{ samples: ['merged PR 1611'] }, { samples: ['reviewed PR 1604'] }] },
  { samples: ['Stripe checkout fails on EUR'], subs: [{ samples: ['invoice webhook retries'] }] },
];

describe('topic names from Gemini on Vertex', () => {
  it('asks the United States multi-region OpenAI-compatible endpoint of the project, with the bearer token, and reads the names back', async () => {
    const { base, seen } = await stub(() => ({
      status: 200,
      body: { choices: [{ message: { content: '{"topics":[{"name":"PR reviews","subs":["Merges","Reviews"]},{"name":"Billing","subs":["Webhooks"]}]}' } }] },
    }));
    const chat = vertexNamingChat({ project: 'renor-test', baseUrl: base, token: async () => 'tok-1' });
    const names = await chatNamer(chat, TOPIC_NAMING_MODEL)(groups as never);
    expect(names).toEqual({ topics: ['PR reviews', 'Billing'], subs: [['Merges', 'Reviews'], ['Webhooks']] });
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe('/v1/projects/renor-test/locations/us/endpoints/openapi/chat/completions');
    expect(seen[0].auth).toBe('Bearer tok-1');
    expect(seen[0].body.model).toBe('google/gemini-3.1-flash-lite');
    expect(seen[0].body.response_format).toEqual({ type: 'json_object' });
  });

  it('throws on a failed call, so the grouping keeps keyword names', async () => {
    const { base } = await stub(() => ({ status: 404, body: { error: { message: 'model not found' } } }));
    const chat = vertexNamingChat({ project: 'renor-test', baseUrl: base, token: async () => 'tok-1' });
    await expect(chatNamer(chat, TOPIC_NAMING_MODEL)(groups as never)).rejects.toThrow(/404/);
  });

  it('throws when the reply carries no text', async () => {
    const { base } = await stub(() => ({ status: 200, body: { choices: [] } }));
    const chat = vertexNamingChat({ project: 'renor-test', baseUrl: base, token: async () => 'tok-1' });
    await expect(chat({ model: TOPIC_NAMING_MODEL, messages: [], temperature: 0 })).rejects.toThrow(/no text/);
  });

  it('refuses a project or location that is not a plain id, and a plain-http endpoint off loopback', () => {
    const token = async () => 'x';
    expect(() => vertexNamingChat({ project: 'a/../b', token })).toThrow(/plain ids/);
    expect(() => vertexNamingChat({ project: 'p', location: 'us central', token })).toThrow(/plain ids/);
    expect(() => vertexNamingChat({ project: 'p', baseUrl: 'http://example.com', token })).toThrow(/https/);
  });
});
