# Review of `Isonapse/isonapse-public`, with ready-to-apply patches

I reviewed the repository you shared at `54c1d95` (source `bce6109`) in four areas:

* the Hook ADK in Python and TypeScript, against `PROTOCOL.md`;
* the conformance suite;
* the Codex, pi and Hermes reference adapters;
* every document and example policy.

**Every finding below was reproduced.** The four patches in `patches/` apply cleanly with
`git am patches/*.patch` on `54c1d95`. With them applied, all suites pass: Python 40 (2 skipped as
root), TypeScript 40 (2 skipped), conformance 18/18.

> One additional issue is **security-relevant**. Following `SECURITY.md`, it is not described here;
> I have reported it privately, with a fix and a regression test.

## What is already excellent (verified, not assumed)

* **Provenance:** all 83 entries in the two provenance manifests resolve, and their git blob SHAs
  match.
* **Docs vs CLI:** every relative link resolves. Every CLI command and flag used in the docs exists
  in the 0.3.0-beta binary.
* **ADK transport:** the 1 MiB cap is exact (1,048,576 accepted, +1 refused), stderr is capped, the
  process group is SIGKILLed on the deadline, and no orphans remain even when a grandchild holds
  stdout open.
* **Decode strictness:** duplicate keys, lone surrogates, NaN, null optionals and wrong-boundary
  fields are all refused identically in both languages. Decisions are single-use and bound to
  their boundary.
* **Conformance strengths:** the suite already catches merge-instead-of-replace, ignored exit codes,
  garbage or oversized output, and printing the original instead of `updatedOutput`.

## Patch 1: conformance suite (`run.py` + 3 fixtures)

I wrote deliberately **wrong adapters**, each the template with one MUST rule broken, and ran the
suite against them:

| Wrong adapter | Rule broken | Before | After |
| --- | --- | --- | --- |
| accepts unknown decision `"defer"` and runs the action | 3 | **PASS** | FAIL `unknown-decision` |
| treats a missing `protocolVersion` as 1 | response table | **PASS** | FAIL `missing-protocol-version` |
| prints the raw secret result on a post-action `deny` without `updatedOutput` | 6/7 | **PASS** | FAIL `post-deny-without-output` |
| sends `PreToolUse` as the event for every hook | 1 | **PASS** | FAIL handshake |
| sends no event argument at all | 1 | **PASS** | FAIL handshake |

The handshake check verified `--host`/`--adapter-protocol` but never the event argument, and
`expectedHookEvent` was never read. The patch asserts the exact argv. The template still passes,
and the existing anti-theater proof still runs.

**Not patched; proposed for your decision:**

1. **The hung-hook fixture rewards knowing the test seam, not killing the hook.** The stub sleeps
   1 s and then answers allow, so an adapter with the documented 55 s deadline fails unless it
   implements the optional sentinel seam. Meanwhile an adapter that never kills the hung process
   passes. Suggestion: hang far longer than the suite deadline, record the stub's pid, and assert it
   is dead afterwards.
2. **The fixture answer key is visible to the adapter.** `ISONAPSE_FIXTURE`, including `expect`, is
   in the adapter's environment. A roughly 10-line adapter that replays `expect` passes.
   `--fixtures` also accepts any directory with the right file names. HOST-PROFILES treats "a green
   transcript" as evidence, so the PASS line should carry a hash of the fixture set.
3. **No fixture models a declined `ask` approval**, so "proceed on ask without approval" can never
   fail.

## Patch 2: tests assume a non-root uid

Two trust-rule tests fail in both packages when run as root (CI containers). As root, the "user-owned"
fixture directory *is* root-owned, which the rule tolerates by design. `packages.py` runs these with
`check=True`, so a root CI job fails. The patch skips the two tests when root, with the reason
stated.

## Patch 3: Python `check_version` outside the outcome contract

* **Invalid UTF-8:** a `--version` answer with invalid UTF-8 raised `UnicodeDecodeError` out of
  `hook_command`, where the documented contract is an outcome with a `cause`.
* **Non-ASCII digits:** `\d` accepted Arabic-Indic digits (`isonapse-hook ١.٠.٠` → proceed), which
  TypeScript rejects.
* **The fix:** both cases now become a `hook-protocol` refusal, and only ASCII digits match. (The
  TypeScript side of the same fix is part of the private report.)

## Patch 4: documentation contradictions

* **`reference/codex/README.md`:**
  * It said "Nothing warns you" when a Codex host stops being governed, while the same page,
    `INTEGRATION.md` and the CLI describe the `hook status` heuristic warning.
  * Its lifecycle row said "1-3 s budget" for both events, but `hooks.json` gives SessionStart
    60 s.
* **`fields/06-file-patterns.lua`:** said "Five shapes" and lists six.
* **Bug-report template:** the version placeholder is `+main.<sha>`, but real builds are
  `+release.<sha>`.
* **`README.md`:** says `adk-pin` is "Codex CLI only", but it applies to every pin-file ADK host.
* **`HOST-PROFILES.md`:** pointed to a "feature request", but a dedicated "Host adapter or profile"
  template exists.

## Found but deliberately not patched (semantics need a maintainer)

These are in the canonical private repo and synced here, and some depend on engine behaviour I
could not observe without an authenticated host:

* **`fields/02-blocked-capabilities.lua`:**
  * **The claim:** it says "NO agent" may run `sudo`/`dd`.
  * **The code:** the key is `["agent:*"]`, which the same file defines as matching only IDs that
    start with `agent:`. Real IDs look like `claude-code/<session>`.
  * **Likely fix:** `["*"]`. The same key appears in `expressiveness/01` and `05`.
* **`fields/05-action-rules.lua`:** says `pii_allowlist` takes *regex*, but the example uses Lua
  escapes (`127%.0%.0%.1`, `dev%-db`) together with `(a|b)` alternation. Under either reading, only
  `localhost` can match.
* **`fields/06-file-patterns.lua`:** `**/.aws/credentials` cannot match under the file's own rules,
  since a basename never contains `/`.
* **`expressiveness/02-loop-allowlist.lua`:**
  * **The claim:** the README calls this "read-only git".
  * **The code:** the PERMIT covers `git:branch` and `git:stash`, so `branch -D` and `stash drop`
    are also PERMITted, and they skip the destructive veto.
* **Python/TypeScript decode drift:**
  * **Differences:** `protocolVersion: 1.0`/`1e0` is accepted by TypeScript but refused by Python. A
    UTF-8 BOM is accepted by TypeScript and refused by Python. A reason consisting only of `\u001c`
    or U+FEFF is treated differently because `strip()` and `trim()` remove different characters.
  * **Why it matters:** the same Hook answer can authorize in one language and refuse in the other.
    I suggest a shared decode test vector file run by both packages.
* **`examples/policies/README.md`:** contains maintainer text ("edit examples here, never in the
  public repository"), which reads backwards in the public snapshot.
