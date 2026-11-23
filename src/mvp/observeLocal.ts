import fs from 'fs';
import os from 'os';
import path from 'path';
import { loadConfig } from '../config.js';
import { openDb } from '../db/client.js';
import { observeEnabled, storeObservation, type ObserveParams, type ObserveResult } from './observations.js';

/** The most one hook event may weigh on stdin: the hook already trims a prompt to 8 KB, so this is generous and bounded. */
export const OBSERVE_STDIN_MAX_BYTES = 64 * 1024;

/**
 * `renor-engine observe`: take ONE observation from a hook process, with no network and no model call. It goes through
 * storeObservation, the code the hosted `renor/observe` handler runs, so the same secret screening, 8 KB trim, 90-day
 * expiry, 20,000-row cap and idempotency on (session, seq) apply. The store is the engine's own SQLite file in WAL mode, so a
 * running stdio server and any number of these one-shot processes may write at once (better-sqlite3 waits up to 5 s for a lock).
 * Off (RENOR_OBSERVE unset) it does nothing and stores nothing.
 */
export function observeOnce(raw: string, env: NodeJS.ProcessEnv = process.env): ObserveResult {
  const none: ObserveResult = { ok: true, stored: false, duplicate: false, redactions: 0 };
  if (!observeEnabled(env)) return none;
  if (Buffer.byteLength(raw, 'utf8') > OBSERVE_STDIN_MAX_BYTES) return none;
  let params: ObserveParams;
  try { params = JSON.parse(raw) as ObserveParams; } catch { return none; }
  const config = loadConfig();
  const db = openDb(config.dbPath);
  try {
    return storeObservation(db, path.resolve(config.vaultPath), params);
  } finally {
    db.close();
  }
}

/** How many observation rows this workspace holds (for `renor capture status`). 0 when the table does not exist yet. */
export function observationCount(env: NodeJS.ProcessEnv = process.env): number {
  void env;
  const config = loadConfig();
  const db = openDb(config.dbPath);
  try {
    const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='observations'").get();
    if (!exists) return 0;
    const row = db.prepare('SELECT COUNT(*) AS n FROM observations WHERE workspace = ? AND retired = 0').get(path.resolve(config.vaultPath)) as { n: number };
    return row.n;
  } finally {
    db.close();
  }
}

/**
 * The local saving switch, as `renor capture observe on --local` writes it (~/.renor/capture.json: observe and observeLocal both
 * true). An app starts `renor-engine mcp` with no RENOR_OBSERVE in its entry, so the server reads the switch itself: this turns
 * RENOR_OBSERVE on for this process only. An explicit RENOR_OBSERVE (even "0") always wins. Anything unsafe or missing is off,
 * and off, nothing changes: no handler, same tool list, same instructions.
 */
export function applyLocalObserveSwitch(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.RENOR_OBSERVE !== undefined) return false;
  try {
    const home = fs.realpathSync(env.HOME || os.homedir());
    const dir = path.join(home, '.renor');
    const mine = (st: fs.Stats) => typeof process.getuid !== 'function' || st.uid === process.getuid();
    const dirStat = fs.lstatSync(dir);
    if (!dirStat.isDirectory() || !mine(dirStat)) return false;
    const file = path.join(dir, 'capture.json');
    const st = fs.lstatSync(file);
    if (!st.isFile() || !mine(st) || (st.mode & 0o077) !== 0) return false;
    const config = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (config?.observe === true && config?.observeLocal === true) {
      env.RENOR_OBSERVE = '1';
      return true;
    }
  } catch { /* unreadable or absent config is off */ }
  return false;
}

/** Delete every observation record of this workspace (and the summary notes written from them). Returns how many rows went. */
export function purgeAllObservations(): number {
  const config = loadConfig();
  const db = openDb(config.dbPath);
  const workspace = path.resolve(config.vaultPath);
  try {
    const exists = (name: string) => db.prepare("SELECT 1 FROM sqlite_master WHERE name = ?").get(name) !== undefined;
    if (!exists('observations')) return 0;
    const notes = exists('observation_summaries')
      ? (db.prepare('SELECT note_path FROM observation_summaries WHERE workspace = ?').all(workspace) as Array<{ note_path: string }>) : [];
    const count = db.transaction(() => {
      if (exists('observations_fts')) db.prepare('DELETE FROM observations_fts WHERE workspace = ?').run(workspace);
      if (exists('observation_summaries')) db.prepare('DELETE FROM observation_summaries WHERE workspace = ?').run(workspace);
      return db.prepare('DELETE FROM observations WHERE workspace = ?').run(workspace).changes;
    })();
    for (const note of notes) {
      const target = path.resolve(workspace, note.note_path);
      if (target.startsWith(workspace + path.sep)) { try { fs.rmSync(target, { force: true }); } catch { /* already gone */ } }
    }
    return count;
  } finally {
    db.close();
  }
}
