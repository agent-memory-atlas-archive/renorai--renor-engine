import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const on = value => value === true || ['1', 'true', 'on', 'yes'].includes(String(value ?? '').trim().toLowerCase());
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
/** True when this user owns the entry (always true where the platform has no uids). */
export const ownedByMe = st => typeof process.getuid !== 'function' || st.uid === process.getuid();

/** The owner's home directory with every symlink resolved, once; null when it is not an existing directory. */
export function realHome(env = process.env) {
  try {
    return fs.realpathSync(env.HOME || os.homedir());
  } catch {
    return null;
  }
}

/**
 * The text of a file the owner wrote: never a symlink, a regular file owned by this user, and (with `privateOnly`) no
 * group or other access. The lstat is taken before the open and the open refuses a final symlink (O_NOFOLLOW), and the
 * opened descriptor must still be the file that was checked. Anything else reads as null.
 */
export function readOwnedFile(file, { privateOnly = false } = {}) {
  let before;
  try {
    before = fs.lstatSync(file);
  } catch {
    return null;
  }
  if (!before.isFile() || !ownedByMe(before) || (privateOnly && (before.mode & 0o077) !== 0)) return null;
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.ino !== before.ino || opened.dev !== before.dev) return null;
    return fs.readFileSync(fd, 'utf8');
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** The key lives at exactly ~/.renor/key. A keyFile naming anything else (absolute, traversing, or another path) is refused. */
const KEY_NAMES = new Set(['~/.renor/key', '.renor/key']);

/** Fill hook settings from the owner's private capture file. Explicit environment values always win. */
export function captureEnvironment(base = process.env) {
  const env = { ...base };
  const home = realHome(base);
  const renor = home ? path.join(home, '.renor') : null;
  // ~/.renor itself must be a real directory: a symlink there would move the config and the key elsewhere.
  let renorIsDir = false;
  try {
    renorIsDir = renor !== null && fs.lstatSync(renor).isDirectory() && ownedByMe(fs.lstatSync(renor));
  } catch {
    renorIsDir = false;
  }
  let config = {};
  if (renorIsDir) {
    try {
      const parsed = JSON.parse(readOwnedFile(path.join(renor, 'capture.json'), { privateOnly: true }) ?? 'null');
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) config = parsed;
    } catch { /* invalid JSON means the safe, off defaults */ }
  }
  if (env.RENOR_SAVE_HOOK === undefined && on(config.saveHook)) env.RENOR_SAVE_HOOK = '1';
  if (env.RENOR_STANDING_RULES_HOOK === undefined && on(config.rulesHook)) env.RENOR_STANDING_RULES_HOOK = '1';
  if (env.RENOR_AUTO_RECALL === undefined && on(config.autoRecall)) env.RENOR_AUTO_RECALL = '1';
  if (env.RENOR_CAPTURE_MODE === undefined && ['off', 'user', 'server', 'alternate', 'trial'].includes(config.mode)) env.RENOR_CAPTURE_MODE = config.mode;
  if (env.RENOR_CAPTURE_EVERY_TURNS === undefined && Number.isInteger(config.everyTurns) && config.everyTurns > 0) env.RENOR_CAPTURE_EVERY_TURNS = String(config.everyTurns);
  if (env.RENOR_CONNECT_TOKEN === undefined && renorIsDir) {
    const named = config.keyFile === undefined ? '~/.renor/key' : config.keyFile;
    if (typeof named === 'string' && KEY_NAMES.has(named)) {
      const token = readOwnedFile(path.join(renor, 'key'), { privateOnly: true });
      if (token !== null) env.RENOR_CONNECT_TOKEN = token.trim();
    }
  }
  const skip = Array.isArray(config.skipWhenEnv) ? config.skipWhenEnv : [];
  return { env, skip: skip.some(name => typeof name === 'string' && name && base[name] !== undefined) };
}

const OFF = ['0', 'off', 'false', 'no']

/**
 * Observation capture is on by default (owner rule, 4 Nov 2026). It is off when RENOR_OBSERVE is 0|off|false|no, when
 * ~/.renor/capture.json says `"observe": false`, or when ~/.renor is not a real directory of ours / capture.json is
 * not a private JSON object we own (unsafe config is off). RENOR_OBSERVE=1|on|true|yes wins over the file.
 */
export function observeEnabled(env = process.env) {
  const asked = String(env.RENOR_OBSERVE ?? '').trim().toLowerCase()
  if (OFF.includes(asked)) return false
  const home = realHome(env)
  if (!home) return false
  const dir = path.join(home, '.renor')
  try {
    let st = null
    try { st = fs.lstatSync(dir) } catch (err) { if (err?.code !== 'ENOENT') return false }
    if (st && (!st.isDirectory() || !ownedByMe(st))) return false
    if (['1', 'on', 'true', 'yes'].includes(asked)) return true
    if (!st) return true
    const file = path.join(dir, 'capture.json')
    try { fs.lstatSync(file) } catch (err) { return err?.code === 'ENOENT' }
    const raw = readOwnedFile(file, { privateOnly: true })
    if (raw === null) return false
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false
    return !(parsed.observe === false || (typeof parsed.observe === 'string' && OFF.includes(parsed.observe.trim().toLowerCase())))
  } catch { return false }
}

/**
 * True only when the person turned observation on themselves: RENOR_OBSERVE=1|on|true|yes, or "observe": true in a
 * private capture.json. Default-on (no file, or a file with no `observe`) is not explicit. Cursor and Gemini CLI hooks
 * install only on this stronger signal, because the default-on privacy sentence names Claude Code and Codex only.
 */
export function observeExplicit(env = process.env) {
  if (!observeEnabled(env)) return false
  const ON = ['1', 'on', 'true', 'yes']
  if (ON.includes(String(env.RENOR_OBSERVE ?? '').trim().toLowerCase())) return true
  const home = realHome(env)
  if (!home) return false
  try {
    const raw = readOwnedFile(path.join(home, '.renor', 'capture.json'), { privateOnly: true })
    if (raw === null) return false
    const v = JSON.parse(raw).observe
    return v === true || (typeof v === 'string' && ON.includes(v.trim().toLowerCase()))
  } catch { return false }
}

/**
 * Where observation goes: true when the owner chose the self-hosted engine on this computer (`renor capture observe on --local`,
 * or `renor connect --local` with the switch on). Anything else, unsafe config included, is the hosted gateway as before.
 */
export function observeLocal(env = process.env, { anySwitch = false } = {}) {
  if (!anySwitch && !observeEnabled(env)) return false;
  const home = realHome(env);
  if (!home) return false;
  try {
    const raw = readOwnedFile(path.join(home, '.renor', 'capture.json'), { privateOnly: true });
    return raw !== null && JSON.parse(raw).observeLocal === true;
  } catch { return false; }
}
