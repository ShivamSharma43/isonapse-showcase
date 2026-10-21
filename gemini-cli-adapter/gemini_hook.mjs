#!/usr/bin/env node
// Community adapter: Google Gemini CLI hooks -> Isonapse Host Adapter Protocol v1.
// Apache-2.0. "Compatible with Isonapse Host Adapter Protocol v1"; not an official
// Isonapse component.
//
// Gemini CLI (proven against @google/gemini-cli-core 0.64.0) starts ONE fresh
// process per hook event through the user's shell, writes one JSON event on
// stdin and reads the answer from stdout/stderr and the exit status. This file
// maps Gemini's vocabulary onto the canonical events the shipped
// `@isonapse/hook-adk` `hook-command` helper understands, and renders Gemini's
// wire format back. All transport, pinning and decision application come from
// the ADK.
//
// What we learned from reading Gemini's hook runner (hooks/hookRunner.js,
// scheduler/hook-utils.js, core/coreToolHookTriggers.js) and pin in tests:
//
//   * Gemini FAILS OPEN on a crash-free failure: a timeout, a spawn error and
//     exit status 1 all let the tool run. Exit 2 (or any status >= 2) with a
//     plain-text stderr and an empty stdout is a deny. Every path below ends in
//     an explicit answer; the outer catch is exit 2 with plain-text stderr.
//   * BeforeTool CAN rewrite input exactly: the scheduler rebuilds the
//     invocation from `hookSpecificOutput.tool_input` alone (`tool.build`), so
//     a removed key stays removed.
//   * BeforeTool CAN ask: `decision: "ask"` forces Gemini's native confirmation
//     dialog (`forcedDecision: "ask_user"`) even when policy would allow.
//     Headless runs (`gemini -p`) have no dialog, so `--no-ask` turns ask into
//     deny for them.
//   * AfterTool can NOT replace a result, only block it (withhold) or append
//     context. An output replacement is therefore a withhold here.
//   * Gemini events carry NO tool-call id. Pre/post pairing is done by an
//     owner-only per-session ledger keyed on the exact effective input (see
//     `Ledger`). A post event with no matching pre is withheld (fail closed).
//
// Registered capability boundary: --input-replacement and (interactive only)
// --approval. Never --output-replacement.
import {createHash, randomBytes} from "node:crypto";
import {mkdir, open, readFile, rename, rm, stat, writeFile} from "node:fs/promises";
import {homedir} from "node:os";
import {isAbsolute, join, resolve} from "node:path";

const EVENT_MAP = {SessionStart: "SessionStart", SessionEnd: "SessionEnd", BeforeTool: "PreToolUse", AfterTool: "PostToolUse"};
// Gemini's default hook timeout is 60 s; the ADK transport deadline is 50 s.
// SessionStart is two exchanges (version probe + decision): 25 s each.
const SESSION_START_EXCHANGE_MS = 25_000;
const LOCK_BUDGET_MS = 3_000;
const MAX_PENDING_PER_SESSION = 512;

const json = value => JSON.stringify(value);
const sha256 = text => createHash("sha256").update(text).digest("hex");
const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);
const canonical = value => JSON.stringify(value, (_key, item) =>
  isObject(item) ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
const sentence = text => String(text).trim().replace(/\.$/, "");
const shellQuote = text => `'${String(text).replaceAll("'", `'"'"'`)}'`;
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;

// ---------------------------------------------------------------------------
// Gemini tool vocabulary -> canonical Isonapse tool vocabulary
// ---------------------------------------------------------------------------

/** Map one Gemini tool call to `{tool_name, tool_input}` the policy engine knows. */
export function mapTool(payload, Refused) {
  const {tool_name: name, tool_input: input, cwd, mcp_context: mcp} = payload;
  if (typeof name !== "string" || !isObject(input)) throw new Refused("tool call without a tool name and input object");
  const abs = path => {
    if (typeof path !== "string" || !path) throw new Refused(`${name} needs a file path`);
    if (isAbsolute(path)) return resolve(path);
    if (typeof cwd !== "string" || !isAbsolute(cwd)) throw new Refused(`${name} needs the session cwd to resolve its path`);
    return resolve(cwd, path);
  };
  switch (name) {
    case "run_shell_command": {
      if (typeof input.command !== "string") throw new Refused("run_shell_command without a command string");
      // dir_path is model-authored. Rather than trusting it as the request cwd,
      // fold it into the analysed command so policy sees what really runs.
      const command = input.dir_path ? `cd ${shellQuote(input.dir_path)} && ${input.command}` : input.command;
      return {tool_name: "Bash", tool_input: {command}};
    }
    case "write_file":
      if (typeof input.content !== "string") throw new Refused("write_file without string content");
      return {tool_name: "Write", tool_input: {file_path: abs(input.file_path), content: input.content}};
    case "replace":
      return {tool_name: "Edit", tool_input: {file_path: abs(input.file_path), old_string: input.old_string, new_string: input.new_string, replace_all: input.allow_multiple === true}};
    case "read_file":
      return {tool_name: "Read", tool_input: {file_path: abs(input.file_path)}};
    case "web_fetch": {
      // Gemini's web_fetch takes up to 20 URLs inside free text. Mapping only the
      // first would let the rest bypass policy, so one URL per call is required.
      const urls = [...new Set(String(input.prompt ?? "").match(URL_RE) ?? [])];
      if (urls.length !== 1) throw new Refused(`web_fetch must name exactly one URL per call (found ${urls.length}); split the request`);
      return {tool_name: "WebFetch", tool_input: {url: urls[0], prompt: input.prompt}};
    }
    default:
      // MCP tools: use the runtime-supplied server identity, never the
      // model-visible flattened name (mcp_<server>_<tool> is ambiguous when the
      // server name itself contains '_').
      if (isObject(mcp) && typeof mcp.server_name === "string" && typeof mcp.tool_name === "string") {
        return {tool_name: `mcp__${mcp.server_name}__${mcp.tool_name}`, tool_input: input};
      }
      if (name.startsWith("mcp_")) throw new Refused("MCP tool call without runtime mcp_context");
      // glob, grep_search, list_directory, google_web_search, ... pass through
      // under their own name (capability `tool:<name>`).
      return {tool_name: name, tool_input: input};
  }
}

/** Render an authorized canonical replacement back into Gemini's exact input, or refuse. */
export function renderReplacement(payload, mapped, selected, Refused) {
  const original = payload.tool_input;
  switch (payload.tool_name) {
    case "run_shell_command": {
      if (Object.keys(selected).length !== 1 || typeof selected.command !== "string") throw new Refused("rewritten shell input is not a single command string");
      // The cd-prefix (if any) is already part of the rewritten command, so
      // dir_path is dropped. Presentation-only keys are kept.
      const out = {command: selected.command};
      if (typeof original.description === "string") out.description = original.description;
      if (typeof original.is_background === "boolean") out.is_background = original.is_background;
      return out;
    }
    case "write_file":
      if (canonical(Object.keys(selected).sort()) === canonical(["content", "file_path"]) && selected.file_path === mapped.tool_input.file_path && typeof selected.content === "string") {
        return {file_path: selected.file_path, content: selected.content};
      }
      throw new Refused("rewritten write_file input cannot be applied exactly");
    case "replace":
      if (selected.file_path === mapped.tool_input.file_path && typeof selected.old_string === "string" && typeof selected.new_string === "string") {
        const out = {file_path: selected.file_path, old_string: selected.old_string, new_string: selected.new_string};
        if (selected.replace_all === true) out.allow_multiple = true;
        if (typeof original.instruction === "string") out.instruction = original.instruction;
        return out;
      }
      throw new Refused("rewritten replace input cannot be applied exactly");
    default:
      if (mapped.tool_name.startsWith("mcp__")) return selected;
      throw new Refused(`this host cannot apply a rewritten input for ${payload.tool_name}`);
  }
}

// ---------------------------------------------------------------------------
// Pre/post pairing ledger (Gemini sends no tool-call id)
// ---------------------------------------------------------------------------

/**
 * Owner-only, per-session FIFO of issued tool-call ids keyed by the exact
 * Gemini input that will execute. A pre-event that is authorized pushes an id;
 * the matching post-event pops it. Identical repeated calls pair in order.
 * Lives outside any workspace an agent can write (default ~/.isonapse-gemini).
 */
export class Ledger {
  constructor(dir) { this.dir = dir; }
  key(tool, input) { return sha256(`${tool}\u0000${canonical(input)}`); }
  file(session) { return join(this.dir, `${sha256(session).slice(0, 32)}.json`); }
  async #withLock(session, fn) {
    await mkdir(this.dir, {recursive: true, mode: 0o700});
    const info = await stat(this.dir);
    if ((info.mode & 0o077) !== 0 || (typeof process.getuid === "function" && info.uid !== process.getuid())) {
      throw new Error("ledger directory must be owner-only (0700) and owned by the current user");
    }
    const lock = `${this.file(session)}.lock`;
    const deadline = Date.now() + LOCK_BUDGET_MS;
    for (;;) {
      try { await mkdir(lock, {mode: 0o700}); break; } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        // Break a lock abandoned by a killed adapter (older than the budget).
        try { const s = await stat(lock); if (Date.now() - s.mtimeMs > LOCK_BUDGET_MS * 2) await rm(lock, {recursive: true, force: true}); } catch {}
        if (Date.now() > deadline) throw new Error("ledger lock budget exceeded");
        await new Promise(r => setTimeout(r, 15));
      }
    }
    try {
      let state = {};
      try { state = JSON.parse(await readFile(this.file(session), "utf8")); } catch (error) { if (error?.code !== "ENOENT") throw error; }
      const result = await fn(state);
      const tmp = `${this.file(session)}.${randomBytes(6).toString("hex")}.tmp`;
      await writeFile(tmp, JSON.stringify(state), {mode: 0o600});
      await rename(tmp, this.file(session));
      return result;
    } finally { await rm(lock, {recursive: true, force: true}); }
  }
  async issue(session, tool, input) {
    const id = `gemini-${randomBytes(12).toString("hex")}`;
    await this.#withLock(session, state => {
      const k = this.key(tool, input);
      (state[k] ??= []).push(id);
      const total = Object.values(state).reduce((n, list) => n + list.length, 0);
      if (total > MAX_PENDING_PER_SESSION) throw new Error("too many unpaired tool calls in this session");
    });
    return id;
  }
  async rekey(session, tool, fromInput, toInput, id) {
    await this.#withLock(session, state => {
      const from = this.key(tool, fromInput);
      state[from] = (state[from] ?? []).filter(item => item !== id);
      if (state[from].length === 0) delete state[from];
      (state[this.key(tool, toInput)] ??= []).push(id);
    });
  }
  async pending(session) { return this.#withLock(session, state => Object.values(state).reduce((n, list) => n + list.length, 0)); }
  async take(session, tool, input) {
    return this.#withLock(session, state => {
      const k = this.key(tool, input);
      const id = state[k]?.shift();
      if (state[k]?.length === 0) delete state[k];
      return id;
    });
  }
  async retract(session, tool, input, id) {
    return this.#withLock(session, state => {
      const k = this.key(tool, input);
      if (!state[k]) return;
      state[k] = state[k].filter(item => item !== id);
      if (state[k].length === 0) delete state[k];
    });
  }
  async end(session) { await rm(this.file(session), {force: true}); }
}

// ---------------------------------------------------------------------------
// Gemini wire format
// ---------------------------------------------------------------------------

const deny = (reason, systemMessage) => json({decision: "deny", reason, ...(systemMessage ? {systemMessage} : {})});
const RETRY_NOTE = " If this was the first action of the session or the first after an Isonapse restart, the cold-start check denied it and retrying the same action once proceeds when policy permits it; a policy denial stays denied.";
const retryNote = outcome => outcome.decision?.decision === "deny" ? RETRY_NOTE : "";
const operatorText = outcome => outcome.cause ? `Isonapse: ${outcome.reason}` : outcome.operatorMessage;

/** Handle one Gemini hook event. Returns `{stdout, stderr, exitCode}`. */
export async function handle({adk, hookCommand, client, ledger, payload, allowAsk}) {
  const {Refused} = adk;
  const geminiEvent = payload.hook_event_name;
  const name = EVENT_MAP[geminiEvent];
  if (!name) throw new Refused(`unsupported Gemini hook event ${typeof geminiEvent === "string" ? geminiEvent : "(missing)"}`);
  const event = {...payload, hook_event_name: name};
  const session = payload.session_id;

  if (name === "SessionStart" || name === "SessionEnd") {
    const outcome = await hookCommand(client, event, {checkVersion: name === "SessionStart"});
    if (name === "SessionEnd") await ledger.end(session).catch(() => {});
    const notes = [outcome.operatorMessage, outcome.kind === "refuse" ? `Isonapse: ${outcome.reason}` : null].filter(Boolean);
    return {stdout: notes.length ? json({systemMessage: notes.join(" ")}) : "", stderr: "", exitCode: 0};
  }

  if (name === "PreToolUse") {
    let mapped;
    try { mapped = mapTool(payload, Refused); } catch (error) {
      if (!(error instanceof Refused)) throw error;
      return {stdout: deny(`Isonapse: ${error.message}`), stderr: "", exitCode: 0};
    }
    // Reserve an id for the ORIGINAL input. If the decision rewrites, the id
    // is moved to the rewritten input below.
    const id = await ledger.issue(session, payload.tool_name, payload.tool_input);
    let asked = false;
    const approve = allowAsk ? async () => { asked = true; return true; } : undefined;
    let outcome;
    try {
      outcome = await hookCommand(client, {...event, ...mapped, tool_use_id: id}, {approve});
    } catch (error) { await ledger.retract(session, payload.tool_name, payload.tool_input, id); throw error; }
    const sys = outcome.operatorMessage;
    if (outcome.kind === "refuse") {
      await ledger.retract(session, payload.tool_name, payload.tool_input, id);
      return {stdout: deny(`Isonapse: ${sentence(outcome.reason)}.${retryNote(outcome)}`, operatorText(outcome)), stderr: "", exitCode: 0};
    }
    let replacement;
    if (outcome.kind === "rewrite") {
      try { replacement = renderReplacement(payload, mapped, outcome.input, Refused); } catch (error) {
        await ledger.retract(session, payload.tool_name, payload.tool_input, id);
        if (!(error instanceof Refused)) throw error;
        return {stdout: deny(`Isonapse: ${error.message}`, sys), stderr: "", exitCode: 0};
      }
      // Same id, now keyed on the input Gemini will actually execute (the
      // AfterTool event reports the rebuilt invocation's parameters).
      await ledger.rekey(session, payload.tool_name, payload.tool_input, replacement, id);
    }
    const body = {};
    if (asked) { body.decision = "ask"; body.systemMessage = `Isonapse asks for your approval: ${sentence(outcome.decision?.reason ?? "policy requires a human decision")}.`; }
    else if (sys) body.systemMessage = sys;
    if (replacement) body.hookSpecificOutput = {hookEventName: "BeforeTool", tool_input: replacement};
    return {stdout: Object.keys(body).length ? json(body) : "", stderr: "", exitCode: 0};
  }

  // PostToolUse
  let mapped;
  try { mapped = mapTool(payload, Refused); } catch (error) {
    if (!(error instanceof Refused)) throw error;
    return {stdout: deny(`Isonapse: tool result withheld (${error.message})`), stderr: "", exitCode: 0};
  }
  const id = await ledger.take(session, payload.tool_name, payload.tool_input);
  if (!id) return {stdout: deny("Isonapse: tool result withheld (no authorized pre-action matches this result)"), stderr: "", exitCode: 0};
  const outcome = await hookCommand(client, {...event, ...mapped, tool_use_id: id});
  if (outcome.kind === "deliver") return {stdout: outcome.operatorMessage ? json({systemMessage: outcome.operatorMessage}) : "", stderr: "", exitCode: 0};
  const why = outcome.kind === "replace"
    ? `Isonapse: tool result withheld (an exact replacement is required and Gemini CLI cannot apply it)${outcome.decision?.reason ? `: ${sentence(outcome.decision.reason)}` : ""}`
    : `Isonapse: ${outcome.reason}`;
  return {stdout: deny(why, operatorText(outcome)), stderr: "", exitCode: 0};
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const {parseArgs} = await import("node:util");
    const {values} = parseArgs({options: {
      hook: {type: "string"}, "hook-sha256": {type: "string"}, "hook-sha256-file": {type: "string"},
      host: {type: "string"}, "state-dir": {type: "string"}, "no-ask": {type: "boolean"},
    }, strict: true});
    for (const setting of ["hook", "host"]) if (!values[setting]) throw new Error(`missing operator setting --${setting}`);
    if (!values["hook-sha256"] === !values["hook-sha256-file"]) throw new Error("exactly one of --hook-sha256 and --hook-sha256-file is required");
    const adk = await import("@isonapse/hook-adk");
    const {hookCommand, readHostEvent} = await import("@isonapse/hook-adk/hook-command");
    const payload = await readHostEvent(process.stdin);
    const timeoutMs = payload.hook_event_name === "SessionStart" ? SESSION_START_EXCHANGE_MS : undefined;
    const installed = values["hook-sha256-file"]
      ? adk.InstalledHook.fromPinFile(values.hook, values["hook-sha256-file"])
      : new adk.InstalledHook(values.hook, values["hook-sha256"]);
    const client = new adk.Client(installed, values.host, {timeoutMs});
    const ledger = new Ledger(values["state-dir"] ?? join(homedir(), ".isonapse-gemini", "pairing"));
    const response = await handle({adk, hookCommand, client, ledger, payload, allowAsk: !values["no-ask"]});
    if (response.stderr) process.stderr.write(response.stderr);
    process.stdout.write(response.stdout);
    process.exitCode = response.exitCode;
  } catch (error) {
    // Gemini fails OPEN on exit 1, timeouts and spawn errors. Exit 2 with a
    // plain-text stderr and empty stdout is an explicit deny for BeforeTool and
    // a withheld result for AfterTool.
    const kind = error?.constructor?.name ?? "Error";
    process.stderr.write(`Isonapse: no usable authorization (${kind}); the action was not authorized\n`);
    process.exitCode = 2;
  }
}
