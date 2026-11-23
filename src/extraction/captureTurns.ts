/**
 * The engine's half of server-side end-of-turn capture (POST /internal/capture-turns, reached through the gateway's
 * POST /capture/turns). On when the workspace has a readable RENOR_CAPTURE_KEY_FILE and MVP_INSTANCE_ID; the explicit opt-in (RENOR_CAPTURE_SERVER_OPTIN)
 * is required only with RENOR_CAPTURE_SERVER=0|off|false (captureModel.ts). Without a config nothing is parsed further and no model call is made.
 *
 * Per request, in order: opt-in check (403 capture_not_enabled) → strict body check (400) → secret screen over every turn
 * (a turn with a secret is dropped whole; a scanner failure answers 503 before anything else) → model and cool-down checks →
 * per-call cap and daily cap, both on a conservative maximum cost, reserved under a lock before the call (429) → one model call
 * → settle the reservation to the call's real cost (or keep it whole when the usage is unknown) → save what passes.
 *
 *   observations  saved as dated notes through the normal note writer (source `capture-server`), so the secret guard
 *                 (appendDailyEntry) applies. One whose text repeats one of the last 200 captured saves is skipped
 *                 (equal, or token overlap of at least 0.8 of the longer text). A text the scanner flags is not saved.
 *   rules         saved as new pending `standing rule` facts, only while rule approvals are on (RENOR_RULE_APPROVALS). A
 *                 topic that already has a current fact is skipped: a capture never supersedes or retires an existing fact.
 *
 * What it never does: write the delta. Nothing it receives is stored, logged or echoed; the reply is counts only, and
 * every error answer is a fixed code. Extraction failures save nothing; write failures report partial counts.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type Database from '../db/sqlite';
import { remember, StaleExpectationError } from '../memory/lifecycle';
import { ruleApprovalsEnabled } from '../mvp/ruleApprovals';
import { scanSecrets } from './secretScanner';
import { callNotes, notesMaxUsd, notesUserContent, observationNotesEnabled, priorDigests } from './observationNotes.js';
import { callLinks, linksMaxUsd, linksUserContent, noteLinksEnabled } from './noteLinks.js';
import { callEvolve, evolveMaxUsd, evolveNeighborsEnabled, evolveUserContent } from './evolveNeighbors.js';
import {
  ANTHROPIC_CAPTURE_PRICE_PER_MILLION, capturePrice, captureConfigDigest, captureMaxUsd, captureServerConfig, captureUserContent, extractCapture,
  type CaptureConfig, type CaptureDiagnostics, type CapturePrice,
} from './captureModel';

export const CAPTURE_SOURCE = 'capture-server';
export const CAPTURE_WRITER = 'renor-capture-server';
export const CAPTURE_CLIENT = 'claude-code-hook/1';
/** Outages and repeated content failures pause paid capture calls for this long. */
export const CAPTURE_COOLDOWN_MS = 30_000;
const CONTENT_FAILURE_LIMIT = 3;
const DEDUPE_WINDOW = 200;
const DEDUPE_OVERLAP = 0.8;
const MAX_MESSAGES = 40;
const MAX_MESSAGE_CHARS = 2000;
const MAX_DELTA_CHARS = 12000;
/** RENOR_CAPTURE_VERBATIM_TURNS: the most characters of one user turn kept as a verbatim excerpt. */
export const VERBATIM_EXCERPT_CHARS = 400;
/** A lock older than this was left by a process that died; it is taken over. The lock is held for milliseconds. */
const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 2_000;

/** Research lever, off unless set: store bounded verbatim excerpts of the (already secret-screened) user turns. */
export function verbatimTurnsEnabled(env: NodeJS.ProcessEnv): boolean {
  return /^(1|on|true|yes)$/i.test(env.RENOR_CAPTURE_VERBATIM_TURNS?.trim() ?? '');
}

/** Research lever, off unless set: capture runs once after a session goes quiet instead of on every turn. */
export function backgroundReflectEnabled(env: NodeJS.ProcessEnv): boolean {
  return /^(1|on|true|yes)$/i.test(env.RENOR_CAPTURE_BACKGROUND_REFLECT?.trim() ?? '');
}
/** RENOR_CAPTURE_LOW_VALUE_FILTER: parsed like the other capture levers; unset or anything else is off. */
export function lowValueFilterEnabled(env: NodeJS.ProcessEnv): boolean {
  return /^(1|on|true|yes)$/i.test(env.RENOR_CAPTURE_LOW_VALUE_FILTER?.trim() ?? '');
}

const LOW_VALUE_TURN = /^(hi|hello|hey|thanks|thank you|thx|ok|okay|k|got it|cool|great|nice|perfect|sounds good|will do|lgtm|bye|good morning|good night)( (there|again|so much|a lot|you|all))?[\s.!?,]*$/i;

/**
 * RENOR_CAPTURE_LOW_VALUE_FILTER: drops greetings, bare acknowledgements and repeated turns (rule-based, no model call).
 * Any turn that is not exactly one of those short phrases is kept (a bare yes/no stays: it can answer a question). It runs before the verbatim-excerpt lever, so filler is not saved as an excerpt.
 */
export function dropLowValueTurns<T extends { text: string; role?: string }>(messages: readonly T[]): { kept: T[]; dropped: number } {
  const seen = new Set<string>();
  const kept: T[] = [];
  for (const message of messages) {
    const text = message.text.trim().replace(/\s+/g, ' ').toLowerCase();
    const key = `${message.role ?? ''}:${text}`;
    if (LOW_VALUE_TURN.test(text) || seen.has(key)) continue;
    seen.add(key);
    kept.push(message);
  }
  return { kept, dropped: messages.length - kept.length };
}

/** RENOR_CAPTURE_BACKGROUND_REFLECT: a session with no new turn for this long is captured in one model call. */
export const REFLECT_IDLE_MS = 300_000;

export interface CaptureTurnsDeps {
  env: NodeJS.ProcessEnv;
  /** Test seam for the idle wait of the background-reflection lever. */
  reflectIdleMs?: number;
  /** Where the per-tenant daily total and the per-call ledger live (the auth state directory, never the memory directory). */
  stateDir: string;
  saveNote(text: string, date: string): Promise<void>;
  /** Resolves true when the rule was written as a new pending fact, false when its topic already had a current fact. */
  saveRule(topic: string, text: string): Promise<boolean>;
  /** Research levers RENOR_CAPTURE_EVOLVE_NEIGHBORS, RENOR_CAPTURE_NOTE_LINKS and RENOR_OBSERVATION_NOTES only: the texts of existing notes closest to the new facts. */
  findNeighbors?(texts: string[]): Promise<string[]>;
  fetchImpl?: typeof fetch;
  now?: () => number;
  log?: (line: string) => void;
}

export interface CaptureTurnsAnswer { status: number; body: Record<string, unknown> }

interface Delta { session: string; turn_index: number; messages: Array<{ role: 'user' | 'assistant'; text: string; at: string | null }> }
interface Spend { day: string; usd: number }
type Admission = 'admitted' | 'over' | 'busy';

const normalise = (text: string): string => text.toLowerCase().replace(/[^\p{L}\p{N}\s]/gu, ' ').replace(/\s+/g, ' ').trim();

/** Strict shape check: what the hook sends, and nothing else. */
export function parseDelta(body: unknown): Delta | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  if (b.client !== CAPTURE_CLIENT) return null;
  if (typeof b.session !== 'string' || !/^[0-9a-f]{12}$/.test(b.session)) return null;
  if (!Number.isSafeInteger(b.turn_index) || (b.turn_index as number) < 0) return null;
  if (!Array.isArray(b.messages) || b.messages.length < 1 || b.messages.length > MAX_MESSAGES) return null;
  let total = 0;
  const messages: Delta['messages'] = [];
  for (const m of b.messages) {
    if (!m || typeof m !== 'object') return null;
    const x = m as Record<string, unknown>;
    if (x.role !== 'user' && x.role !== 'assistant') return null;
    if (typeof x.text !== 'string' || x.text.length < 1 || x.text.length > MAX_MESSAGE_CHARS) return null;
    if (x.at !== null && typeof x.at !== 'string') return null;
    total += x.text.length;
    messages.push({ role: x.role, text: x.text, at: x.at as string | null });
  }
  if (total > MAX_DELTA_CHARS) return null;
  return { session: b.session, turn_index: b.turn_index as number, messages };
}

/** The gateway's secret, compared in constant time over digests (so the length does not leak). */
export function gatewaySecretMatches(presented: string, expected: string): boolean {
  if (!presented || !expected) return false;
  const digest = (value: string) => crypto.createHash('sha256').update(value, 'utf8').digest();
  return crypto.timingSafeEqual(digest(presented), digest(expected));
}

function overlap(a: Set<string>, b: Set<string>): number {
  let shared = 0;
  for (const token of a) if (b.has(token)) shared++;
  return shared / Math.max(a.size, b.size, 1);
}

/**
 * Drops every turn the canonical secret scanner flags, whole. It throws when the scanner throws: the caller answers 503, so
 * a broken scanner sends nothing.
 */
export function screenTurns<T extends { text: string }>(messages: readonly T[]): { kept: T[]; dropped: number } {
  const kept: T[] = [];
  let dropped = 0;
  for (const message of messages) {
    if (scanSecrets(message.text) !== null) dropped++;
    else kept.push(message);
  }
  return { kept, dropped };
}

function readSpend(file: string, day: string): Spend {
  try {
    const value = JSON.parse(fs.readFileSync(file, 'utf8')) as Spend;
    if (value.day === day && Number.isFinite(value.usd) && value.usd >= 0) return value;
  } catch { /* no total yet, or an unreadable one: start the day at zero */ }
  return { day, usd: 0 };
}

function writeSpend(file: string, value: Spend): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
}

/**
 * Runs `fn` while holding an exclusive lock file, so two processes sharing the state directory cannot both read the same total
 * and both pass the cap. Undefined when the lock stayed busy for LOCK_WAIT_MS (the caller fails closed).
 */
function withLock<T>(file: string, fn: () => T): T | undefined {
  const lock = `${file}.lock`;
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    let fd: number | undefined;
    try {
      fd = fs.openSync(lock, 'wx', 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      try {
        if (Date.now() - fs.statSync(lock).mtimeMs > LOCK_STALE_MS) fs.rmSync(lock, { force: true });
      } catch { /* the holder released it between the two calls */ }
      if (Date.now() > deadline) return undefined;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      continue;
    }
    try {
      return fn();
    } finally {
      fs.closeSync(fd);
      fs.rmSync(lock, { force: true });
    }
  }
}

/** Adds the reservation to the day's total when it fits under the daily cap. */
function reserveSpend(file: string, day: string, reserve: number, capDay: number): Admission {
  return withLock(file, (): Admission => {
    const before = readSpend(file, day);
    if (before.usd + reserve > capDay) return 'over';
    writeSpend(file, { day, usd: before.usd + reserve });
    return 'admitted';
  }) ?? 'busy';
}

/** Replaces the reservation with the call's charge. Returns false when the lock stayed busy: the reservation then stands. */
function settleSpend(file: string, day: string, reserve: number, charged: number): boolean {
  return withLock(file, () => {
    const settled = readSpend(file, day);
    writeSpend(file, { day, usd: Math.max(0, settled.usd - reserve + charged) });
    return true;
  }) ?? false;
}

/** One line per model call, written before the call and again after it: numbers and labels only. */
function appendCall(file: string, row: Record<string, number | string>): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), ...row })}\n`, { mode: 0o600 });
}

/**
 * Writes one captured rule as a new pending `standing rule` fact. `expectCurrentEvent: null` makes the write conditional on the
 * topic having no current fact, so an existing rule (approved or pending) is never superseded or retired by a capture.
 */
export function captureRuleSaver(db: Database.Database, memoryDir: string, ledgerRelPath: string): (topic: string, text: string) => Promise<boolean> {
  return async (topic, text) => {
    try {
      await remember(db, memoryDir, ledgerRelPath, {
        subject: 'standing rule', predicate: topic, object: text, source: CAPTURE_SOURCE, writer: CAPTURE_WRITER, expectCurrentEvent: null,
      });
      return true;
    } catch (err) {
      if (err instanceof StaleExpectationError) return false;
      throw err;
    }
  };
}

export function createCaptureTurns(deps: CaptureTurnsDeps): (body: unknown) => Promise<CaptureTurnsAnswer> {
  const now = deps.now ?? Date.now;
  const log = deps.log ?? ((line: string) => { process.stderr.write(`${line}\n`); });
  const spendFile = path.join(deps.stateDir, 'capture-spend.json');
  const callsFile = path.join(deps.stateDir, 'capture-calls.jsonl');
  let cooldownUntil = 0;
  let consecutiveContentFailures = 0;
  const recent: Array<{ key: string; tokens: Set<string> }> = [];

  const isDuplicate = (key: string): boolean => {
    const tokens = new Set(key.split(' ').filter(Boolean));
    return recent.some(r => r.key === key || overlap(r.tokens, tokens) >= DEDUPE_OVERLAP);
  };
  const remembered = (key: string): void => {
    recent.push({ key, tokens: new Set(key.split(' ').filter(Boolean)) });
    if (recent.length > DEDUPE_WINDOW) recent.shift();
  };

  /** Background-reflection lever: screened turns held per session until the session goes idle. */
  const sessions = new Map<string, { messages: Delta['messages']; timer: ReturnType<typeof setTimeout> }>();
  const idleMs = deps.reflectIdleMs ?? REFLECT_IDLE_MS;

  const flush = (session: string): void => {
    const held = sessions.get(session);
    if (!held) return;
    sessions.delete(session);
    clearTimeout(held.timer);
    // Same caps, cool-down and spend ledger as a live call; the answer has no reader, failures are logged by `finish`.
    void extractAndSave(held.messages, 0, captureServerConfig(deps.env)).catch(() => { /* logged inside */ });
  };

  const hold = (session: string, messages: Delta['messages']): void => {
    const before = sessions.get(session);
    if (before) clearTimeout(before.timer);
    let kept = [...(before?.messages ?? []), ...messages];
    // Bounded like one live call: the newest messages that fit.
    let chars = 0;
    let from = kept.length;
    while (from > 0 && kept.length - from < MAX_MESSAGES && chars + kept[from - 1].text.length <= MAX_DELTA_CHARS) {
      chars += kept[from - 1].text.length;
      from--;
    }
    kept = kept.slice(from);
    const timer = setTimeout(() => flush(session), idleMs);
    timer.unref?.();
    sessions.set(session, { messages: kept, timer });
  };

  async function extractAndSave(messages: Delta['messages'], verbatimSaved: number, cfg: CaptureConfig | null): Promise<CaptureTurnsAnswer> {
    const diagnostics: CaptureDiagnostics = { stop_reason: null, parsed: false, output_tokens: null };
    const finish = (answer: CaptureTurnsAnswer): CaptureTurnsAnswer => {
      if (answer.status >= 400) log(`[capture] failure ${JSON.stringify({
        error: answer.body.error, ...diagnostics, upstream: undefined,
      })}`);
      return answer;
    };
    try {
      if (!cfg) return finish({ status: 403, body: { error: 'capture_not_enabled' } });

      const price: CapturePrice | undefined = capturePrice(cfg);
      if (!price) return finish({ status: 503, body: { error: 'model_price_unknown' } });
      if (now() < cooldownUntil) return finish({ status: 503, body: { error: 'cooling_down' } });

      const day = new Date(now()).toISOString().slice(0, 10);
      const chars = messages.reduce((n, m) => n + m.text.length, 0);
      const reserve = captureMaxUsd(captureUserContent(messages), price);
      if (reserve > cfg.maxUsdCall) {
        log('[capture] per-call cap reached: the call was not made');
        return finish({ status: 429, body: { error: 'capture_call_cap' } });
      }
      const admission = reserveSpend(spendFile, day, reserve, cfg.maxUsdDay);
      if (admission === 'busy') return finish({ status: 503, body: { error: 'capture_busy' } });
      if (admission === 'over') {
        log('[capture] daily cap reached: the call was not made');
        return finish({ status: 429, body: { error: 'capture_budget' } });
      }
      // The reservation is on record before the call, so a call that dies midway still shows up here.
      appendCall(callsFile, {
        event: 'reserved', config: captureConfigDigest(cfg, price), reserve_usd: reserve, cap_call_usd: cfg.maxUsdCall, cap_day_usd: cfg.maxUsdDay,
        messages: messages.length, chars,
      });

      const result = await extractCapture(messages, cfg, deps.fetchImpl, diagnostics, day);
      log(`[capture] extraction ${JSON.stringify({ ...diagnostics, upstream: undefined })}`);
      // Settle to the real charge when the usage is known and within the reservation; otherwise the whole reservation stands.
      const charged = result?.usd ?? reserve;
      const usageKnown = result !== null && result.usd !== null;
      settleSpend(spendFile, day, reserve, charged);
      appendCall(callsFile, {
        event: 'settled', ok: result ? 1 : 0, usage_known: usageKnown ? 1 : 0,
        in_tokens: result?.inTokens ?? 0, out_tokens: diagnostics.output_tokens ?? 0,
        cache_write_tokens: result?.cacheWriteTokens ?? 0, cache_read_tokens: result?.cacheReadTokens ?? 0,
        usd_est: charged, messages: messages.length, chars,
      });
      if (!result) {
        const contentFailure = ['invalid_json', 'truncated_output'].includes(diagnostics.failure ?? '');
        consecutiveContentFailures = contentFailure ? consecutiveContentFailures + 1 : 0;
        if (!contentFailure || consecutiveContentFailures >= CONTENT_FAILURE_LIMIT) {
          cooldownUntil = now() + CAPTURE_COOLDOWN_MS;
          consecutiveContentFailures = 0;
        }
        return finish({ status: 502, body: diagnostics.upstream ? { error: 'model_unavailable', upstream: diagnostics.upstream } : { error: 'model_unavailable', reason: diagnostics.failure } });
      }
      consecutiveContentFailures = 0;
      if (result.usd === null) return finish({ status: 502, body: { error: 'usage_unknown' } });
      if (result.usd > reserve) return finish({ status: 502, body: { error: 'cost_over_reserve' } });

      const candidates = (diagnostics.observation_candidates ?? 0) + (diagnostics.rule_candidates ?? 0);
      if (candidates > 0 && result.observations.length + result.rules.length === 0) {
        // The model answered but every entry failed validation: not a provider failure, so 200 with the reason and counts only.
        log(`[capture] save_path ${JSON.stringify({ ...diagnostics, upstream: undefined, reason: 'no_valid_entries', saved: 0, pending_rules: 0 })}`);
        return finish({ status: 200, body: { ok: true, saved: 0, pending_rules: 0, reason: 'no_valid_entries', candidates, accepted: 0 } });
      }

      let saved = 0;
      const savedTexts: string[] = [];
      const counts = { empty: 0, duplicate: 0, secret: 0, note_write_failed: 0, rule_write_failed: 0, rule_not_saved: 0, rules_disabled: 0 };
      for (const observation of result.observations) {
        const key = normalise(observation.text);
        if (!key) { counts.empty++; continue; }
        if (isDuplicate(key)) { counts.duplicate++; continue; }
        // The model's output is screened again before it is written.
        if (scanSecrets(observation.text) !== null) { counts.secret++; continue; }
        try {
          await deps.saveNote(observation.text, observation.date);
          remembered(key);
          saved++;
          savedTexts.push(observation.text);
        } catch { counts.note_write_failed++; }
      }

      // Research lever (default off): one more call restates existing notes the new facts made stale, as new dated notes.
      if (evolveNeighborsEnabled(deps.env) && deps.findNeighbors && !cfg.ownHwUrl && savedTexts.length > 0) {
        try {
          const neighbors = (await deps.findNeighbors(savedTexts)).filter(t => !savedTexts.includes(t));
          if (neighbors.length > 0) {
            const content = evolveUserContent(savedTexts, neighbors);
            const evolveReserve = evolveMaxUsd(content, price);
            if (reserveSpend(spendFile, day, evolveReserve, cfg.maxUsdDay) === 'admitted') {
              const evolved = await callEvolve(content, Math.min(neighbors.length, 6), cfg, deps.fetchImpl);
              const p = ANTHROPIC_CAPTURE_PRICE_PER_MILLION[cfg.model];
              const charged = evolved && p && evolved.inTokens !== null && evolved.outTokens !== null
                ? (evolved.inTokens * p.input + evolved.outTokens * p.output) / 1e6 : evolveReserve;
              settleSpend(spendFile, day, evolveReserve, Math.min(charged, evolveReserve));
              appendCall(callsFile, { event: 'evolve', ok: evolved ? 1 : 0, usd_est: charged, updates: evolved?.updates.length ?? 0 });
              for (const text of evolved?.updates ?? []) {
                if (scanSecrets(text) !== null) continue;
                try { await deps.saveNote(text, day); } catch { /* an update that fails to write never fails the capture */ }
              }
            }
          }
        } catch { /* the lever never fails a capture */ }
      }

      // Research lever (default off): one more call writes keywords, a context line and links to close notes, as one new note.
      if (noteLinksEnabled(deps.env) && deps.findNeighbors && !cfg.ownHwUrl && savedTexts.length > 0) {
        try {
          const neighbors = (await deps.findNeighbors(savedTexts)).filter(t => !savedTexts.includes(t)).slice(0, 6);
          const content = linksUserContent(savedTexts, neighbors);
          const linksReserve = linksMaxUsd(content, price);
          if (reserveSpend(spendFile, day, linksReserve, cfg.maxUsdDay) === 'admitted') {
            const linked = await callLinks(content, neighbors, cfg, deps.fetchImpl);
            const p = ANTHROPIC_CAPTURE_PRICE_PER_MILLION[cfg.model];
            const charged = linked && p && linked.inTokens !== null && linked.outTokens !== null
              ? (linked.inTokens * p.input + linked.outTokens * p.output) / 1e6 : linksReserve;
            settleSpend(spendFile, day, linksReserve, Math.min(charged, linksReserve));
            appendCall(callsFile, { event: 'note_links', ok: linked ? 1 : 0, usd_est: charged });
            if (linked && scanSecrets(linked.note) === null) {
              try { await deps.saveNote(linked.note, day); } catch { /* a links note that fails to write never fails the capture */ }
            }
          }
        } catch { /* the lever never fails a capture */ }
      }

      // Research lever (default off): one more call folds the new facts and earlier digests into one running-notes note.
      if (observationNotesEnabled(deps.env) && deps.findNeighbors && !cfg.ownHwUrl && savedTexts.length > 0) {
        try {
          const prior = priorDigests((await deps.findNeighbors(savedTexts)).filter(t => !savedTexts.includes(t)));
          const content = notesUserContent(savedTexts, prior);
          const notesReserve = notesMaxUsd(content, price);
          if (reserveSpend(spendFile, day, notesReserve, cfg.maxUsdDay) === 'admitted') {
            const noted = await callNotes(content, cfg, deps.fetchImpl);
            const p = ANTHROPIC_CAPTURE_PRICE_PER_MILLION[cfg.model];
            const charged = noted && p && noted.inTokens !== null && noted.outTokens !== null
              ? (noted.inTokens * p.input + noted.outTokens * p.output) / 1e6 : notesReserve;
            settleSpend(spendFile, day, notesReserve, Math.min(charged, notesReserve));
            appendCall(callsFile, { event: 'observation_notes', ok: noted ? 1 : 0, usd_est: charged });
            if (noted && scanSecrets(noted.note) === null) {
              try { await deps.saveNote(noted.note, day); } catch { /* a notes note that fails to write never fails the capture */ }
            }
          }
        } catch { /* the lever never fails a capture */ }
      }

      let pending = 0;
      if (ruleApprovalsEnabled(deps.env)) {
        for (const rule of result.rules) {
          if (scanSecrets(rule.text) !== null || scanSecrets(rule.topic) !== null) { counts.secret++; continue; }
          try {
            if (await deps.saveRule(rule.topic.replace(/ /g, '_'), rule.text)) pending++;
            else counts.rule_not_saved++;
          } catch { counts.rule_write_failed++; }
        }
      } else counts.rules_disabled = result.rules.length;
      const savePath = {
        ...diagnostics, upstream: undefined, ...counts, saved, pending_rules: pending,
        reason: counts.note_write_failed + counts.rule_write_failed > 0 ? 'write_failed'
          : saved + pending > 0 ? 'saved'
          : result.observations.length + result.rules.length === 0 ? 'empty_extraction' : 'nothing_persisted',
      };
      log(`[capture] save_path ${JSON.stringify(savePath)}`);
      if (counts.note_write_failed + counts.rule_write_failed > 0) {
        return finish({ status: 500, body: { error: 'capture_save_failed', saved, pending_rules: pending } });
      }
      return finish({ status: 200, body: { ok: true, saved: saved + verbatimSaved, pending_rules: pending } });
    } catch {
      return finish({ status: 500, body: { error: 'capture_failed' } });
    }
  }

  const early = (answer: CaptureTurnsAnswer): CaptureTurnsAnswer => {
    if (answer.status >= 400) log(`[capture] failure ${JSON.stringify({ error: answer.body.error, stop_reason: null, parsed: false, output_tokens: null, upstream: undefined })}`);
    return answer;
  };

  return async function handle(body: unknown): Promise<CaptureTurnsAnswer> {
    try {
      const cfg: CaptureConfig | null = captureServerConfig(deps.env);
      if (!cfg) return { status: 403, body: { error: 'capture_not_enabled' } };
      const delta = parseDelta(body);
      if (!delta) return { status: 400, body: { error: 'invalid_body' } };
      // Screened before any spend, log or provider call. Only the count of turns held back is logged, never their text.
      let screened: { kept: Delta['messages']; dropped: number };
      try {
        screened = screenTurns(delta.messages);
      } catch {
        return early({ status: 503, body: { error: 'scanner_unavailable' } });
      }
      if (screened.dropped > 0) log(`[capture] ${screened.dropped} turn(s) held back by the secret scanner: not sent`);
      if (screened.kept.length === 0) log('[capture] save_path {"reason":"all_turns_screened","saved":0,"pending_rules":0}');
      if (screened.kept.length === 0) return early({ status: 200, body: { ok: true, saved: 0, pending_rules: 0 } });
      let messages = screened.kept;
      if (lowValueFilterEnabled(deps.env)) {
        const filtered = dropLowValueTurns(messages);
        if (filtered.dropped > 0) log(`[capture] ${filtered.dropped} low-value turn(s) dropped by the filter`);
        if (filtered.kept.length === 0) return early({ status: 200, body: { ok: true, saved: 0, pending_rules: 0 } });
        messages = filtered.kept;
      }

      // Lever (default off, no model call): a bounded verbatim excerpt of each screened user turn, saved as a dated note.
      let verbatimSaved = 0;
      if (verbatimTurnsEnabled(deps.env)) {
        const verbatimDay = new Date(now()).toISOString().slice(0, 10);
        for (const message of messages) {
          if (message.role !== 'user') continue;
          const excerpt = message.text.trim().slice(0, VERBATIM_EXCERPT_CHARS);
          const key = normalise(excerpt);
          if (!key || isDuplicate(key)) continue;
          if (scanSecrets(excerpt) !== null) continue;
          try {
            await deps.saveNote(`User said: ${excerpt}`, verbatimDay);
            remembered(key);
            verbatimSaved++;
          } catch { /* a failed excerpt write never blocks the model capture */ }
        }
      }

      if (backgroundReflectEnabled(deps.env)) {
        hold(delta.session, messages);
        return { status: 200, body: { ok: true, saved: verbatimSaved, pending_rules: 0 } };
      }
      return await extractAndSave(messages, verbatimSaved, cfg);
    } catch {
      return early({ status: 500, body: { error: 'capture_failed' } });
    }
  };
}
