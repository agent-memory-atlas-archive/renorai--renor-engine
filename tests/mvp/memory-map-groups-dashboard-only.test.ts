import { describe, it, expect, afterEach } from 'vitest';
import { named, restoreEnv, startWorkspace, type Harness } from '../helpers/hiveHarness';

/**
 * memory_map's `groups` (the dashboard's topic map) is listed only to the dashboard's own sessions, the calls the gateway
 * marks: an agent's tool listing, and what it may pass, are unchanged.
 */

const MARK = { 'x-renor-internal': '1' };
let ws: Harness | undefined;
afterEach(async () => {
  await ws?.close();
  ws = undefined;
  restoreEnv();
});

async function mapArgs(headers: Record<string, string>): Promise<string[]> {
  const client = await ws!.connect(headers);
  const { tools } = await client.listTools();
  const map = tools.find((t) => t.name === 'memory_map')!;
  return Object.keys((map.inputSchema as { properties?: Record<string, unknown> }).properties ?? {}).sort();
}

describe('memory_map groups', () => {
  it('is listed to the dashboard and to no agent', async () => {
    ws = await startWorkspace();
    expect(await mapArgs({ ...named('dashboard-inventory-read'), ...MARK })).toContain('groups');
    expect(await mapArgs(named('codex'))).not.toContain('groups');
  });

  it('an agent that passes it gets the map without groups', async () => {
    ws = await startWorkspace();
    const client = await ws.connect(named('codex'));
    const reply = await ws.call(client, 'memory_map', { groups: true });
    expect(reply.isError, reply.raw).toBe(false);
    expect(reply.body).not.toHaveProperty('groups');
  });

  it('the dashboard gets groups (null for a workspace too small for topics)', async () => {
    ws = await startWorkspace();
    const client = await ws.connect({ ...named('dashboard-inventory-read'), ...MARK });
    const reply = await ws.call(client, 'memory_map', { groups: true });
    expect(reply.isError, reply.raw).toBe(false);
    expect(reply.body).toHaveProperty('groups', null);
  });
});
