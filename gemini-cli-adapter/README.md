# Gemini CLI adapter for Isonapse

A community adapter that puts **Google Gemini CLI** under Isonapse governance through the
open-source Hook ADK (Host Adapter Protocol v1). It is built the same way as the maintained
Codex reference: a hook-command adapter using `@isonapse/hook-adk/hook-command` for transport,
pinning and decision handling. This file only translates Gemini's vocabulary and wire format.

> Compatible with Isonapse Host Adapter Protocol v1. This is a community adapter, not an official
> Isonapse component.

## Why Gemini CLI

Gemini CLI is a widely used coding agent that Isonapse does not yet support, and it turns out to be
a **more capable hook-command host than the Codex reference**: it can ask a human and rewrite input
exactly. I read its hook runtime source (`@google/gemini-cli-core@0.64.0`: `hooks/hookRunner.js`,
`scheduler/hook-utils.js`, `scheduler/scheduler.js`, `core/coreToolHookTriggers.js`) and the
test suite pins each fact below, so a Gemini upgrade that changes one of them fails a test.

| Capability | Gemini CLI 0.64.0 | Codex CLI 0.155.1 (reference) |
| --- | --- | --- |
| Block a tool call | ✅ `decision: "deny"` | ✅ |
| Rewrite input exactly | ✅ the scheduler rebuilds the call from `hookSpecificOutput.tool_input` alone (`tool.build`), so a removed key stays removed | ✅ (shell, single-file patch, MCP) |
| Ask a human | ✅ `decision: "ask"` forces Gemini's own confirmation dialog, even where its policy would allow | ❌ becomes a refusal |
| Replace a tool result | ❌ can only block (withhold) it or append context | ❌ withhold only |
| Fails open? | **Yes**: on a timeout, a spawn error and **exit status 1** | Yes |
| Tool-call id in events | **None** (see "Pairing" below) | `tool_use_id` |

Profile to register: `--input-replacement --approval` (interactive) or `--input-replacement` only
for headless `gemini -p` runs, together with the adapter's `--no-ask`.

## How it maps Gemini to Isonapse

| Gemini event / tool | Canonical | Notes |
| --- | --- | --- |
| `BeforeTool` / `AfterTool` | `PreToolUse` / `PostToolUse` | |
| `SessionStart` / `SessionEnd` | same | version probe at start; pairing ledger cleared at end |
| `run_shell_command {command, dir_path?}` | `Bash {command}` | a model-written `dir_path` is **folded into the analysed command** (`cd '<dir>' && …`) instead of being trusted as the session cwd |
| `write_file`, `replace`, `read_file` | `Write`, `Edit`, `Read` | paths made absolute against the runtime cwd, so file-pattern rules apply |
| `web_fetch {prompt}` | `WebFetch {url, prompt}` | Gemini allows up to 20 URLs in free text. Mapping only the first would let the others slip past domain rules, so **exactly one URL per call** is required |
| `mcp_<server>_<tool>` | `mcp__<server>__<tool>` | named from Gemini's **runtime** `mcp_context`, never from the flattened model-visible name (which is ambiguous when a server name contains `_`) |
| anything else | passed through as `tool:<name>` | |
| any other hook event | refused (exit 2) | |

### Pairing pre and post without a tool-call id

Gemini's hook payloads carry no tool-call id, but the ADK (rightly) requires one so a result can be
bound to the authorization that permitted it. The adapter therefore keeps a **per-session pairing
ledger**: an owner-only (`0700`/`0600`) FIFO, outside any workspace, keyed by the exact input
Gemini will execute.

* An authorized `BeforeTool` mints a random id, keyed on the input that will actually run. After a
  rewrite, the id is re-keyed to the rewritten input, which is what `AfterTool` reports.
* `AfterTool` pops the matching id. **No match means the result is withheld.** A forged or replayed
  result event never reaches the model, and a denied call leaves nothing to pair with.
* Identical repeated calls pair in order. Parallel tool calls are serialised by a lock with a
  bounded wait, and a stale lock left by a killed adapter is broken.

### Failing closed on a fail-open host

Gemini treats exit 1, a timeout and a spawn failure as **allow**. So every path in the adapter ends
in an explicit answer, and the outer `catch`, including a failed import of the ADK, exits **2** with
a plain-text stderr, which Gemini treats as a deny. The adapter's deadline (50 s transport, or 25 s
per SessionStart exchange) sits below Gemini's 60 s hook timeout, so the adapter answers before
Gemini gives up.

## Tests: 15 end-to-end, against Gemini's real hook runner

```sh
npm install                      # @isonapse/hook-adk from the release toolkit + @google/gemini-cli-core (dev)
npm test
```

The tests do not mock Gemini. They instantiate **Gemini's own `HookRunner`**, which spawns the
adapter through a shell exactly as Gemini does. The verdict is read through Gemini's own
`getBlockingError()`, `getModifiedToolInput()` and `isAskDecision()`. On the other side, a pinned
stub `isonapse-hook` serves the canned Protocol v1 answers through the real ADK transport, with its
SHA-256 pin and path-trust checks active.

| # | Case |
| --- | --- |
| 1 | allow: unchanged, pre and post share one `tool_use_id` |
| 2 | deny: blocked, the model sees the reason |
| 3 | rewrite: Gemini runs exactly `effectiveInput`, and post pairs on the rewritten input |
| 4 | `dir_path` folded into the analysed command |
| 5–6 | ask: Gemini's native dialog; `--no-ask` refuses (headless) |
| 7 | output replacement → withheld; `read_file .env` is mapped to an absolute `Read` |
| 8–9 | a post with no authorized pre, or after a deny, is withheld without asking the Hook |
| 10–11 | Hook crash and **pin mismatch** fail closed |
| 12 | multi-URL `web_fetch` refused |
| 13 | MCP named from runtime `mcp_context` |
| 14 | unknown event: exit 2, deny |
| 15 | **pins Gemini's fail-open on exit 1**, the reason for all of the above |

A mutation check (changing the fail-closed exit code to 1) turns the suite red.

```
# pass 15
# fail 0
```

## Install (operator terminal, never from inside the agent)

```sh
# 1. adapter + ADK copy in a directory only you can write
mkdir -p ~/.isonapse-gemini && cd ~/.isonapse-gemini
cp /path/to/gemini_hook.mjs /path/to/render-settings.mjs /path/to/settings.hooks.template.json .
tar -xzf ~/.isonapse/bin/isonapse-adapter-toolkit.tar.gz
npm install --offline --ignore-scripts ./isonapse-adapter-toolkit/typescript/isonapse-hook-adk-1.1.0.tgz

# 2. register the profile (asks for OS authentication) and restart
NODE="$(command -v node)"   # must be an owner-controlled, non-symlinked node, see HOST-PROFILES.md
isonapse hook host-profile create gemini --executable "$NODE" --script "$PWD/gemini_hook.mjs" \
  --input-replacement --approval > gemini-profile.json
isonapse hook host-profile register gemini-profile.json && isonapse hook restart
isonapse hook adk-pin       # writes ~/.isonapse/adk/hook.sha256

# 3. wire Gemini (prints merged settings; review, then save)
node render-settings.mjs --node "$NODE" --adapter "$PWD/gemini_hook.mjs" \
  --hook "$(sed -n 's/^hook_binary_path = "\(.*\)"/\1/p' ~/.isonapse/config.toml)" \
  --pin-file ~/.isonapse/adk/hook.sha256 --host "$(isonapse hook host-profile list | grep -o 'adk-gemini-[a-z0-9]*' | head -1)" \
  --settings ~/.gemini/settings.json > /tmp/gemini-settings.json
```

Then do one harmless action in Gemini and confirm that `isonapse hook report --host <id>` shows a
receipt.

## Limits (stated plainly)

* **Gemini fails open** on exit 1, timeouts and spawn errors. If the adapter cannot be started at all
  (for example `node` was deleted), Gemini runs the tool. `isonapse hook status` warnings and
  receipt checks are the backstop, as for Codex.
* A tool **result** cannot be rewritten (for example to redact a secret). It can only be withheld
  whole.
* Not yet run against a live Isonapse daemon with real Gemini sessions. In my sandbox the daemon's
  ingress authentication (correctly) refused processes that were not a registered host, and
  registration needs interactive OS authentication. The protocol behaviour is proven against
  Gemini's real runner and the real ADK; the live receipt check is the next step.
