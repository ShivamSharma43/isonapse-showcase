# Isonapse 0.3.0-beta: hands-on assessment

**Author:** Shivam Sharma · **Build tested:** `isonapse 0.3.0-beta+release.bce6109` (public `main`),
x86_64 Linux (glibc 2.39), Hook ADK 1.1.0 · **Date:** 20 Oct 2026

## TL;DR

* **The core holds up under attack.** I ran five tamper drills against a real witness chain
  (edit a decision, edit a description, delete a middle receipt, truncate the tail, swap the key),
  plus a rollback that also strips the signed head. **All six were detected** by the offline
  verifier. Ingress authentication refused my attempt to replay Claude Code events from a
  non-Claude process, *before* policy ran. The policy engine rejects malformed policies with
  precise errors.
* **The edges are where adoption will break:** installation behind a token or firewall, running as
  root in containers, a broken policy that only logs a WARN, and no offline policy check. All of
  these are fixable, and each has a proposal below.
* **I built three things on top of it:**
  1. **Gemini CLI adapter**: a new host via the Hook ADK. 15 end-to-end tests against Gemini's
     *real* hook runner.
  2. **Injection firewall**: a goal-organised Lua policy plus a red-team harness that scores
     results from ground truth.
  3. **Policy guard Action**: catches a PR that widens agent powers, validates the policy with the
     real engine, and detects rolled-back or re-keyed evidence. 26 tests, using real engine and
     real chains.

---

## 1. What I ran (evidence, not claims)

| # | Experiment | Result |
| --- | --- | --- |
| E1 | Install via `install.sh` | ❌ failed: see F-1. ✅ Then installed from the Homebrew formula's pinned URL with **SHA-256 verified** (`c331de07…ce95e`). |
| E2 | `hook init` / `hook start` | ❌ blocked by the model download (F-2), then by running as root (F-4). The daemon itself starts in about 1 s via `hook serve`. |
| E3 | Load `exfil-firewall.lua` into the engine | ✅ `Policy loaded from verified file snapshot` |
| E4 | Load a policy with `decision = "MAYBE"` | ✅ rejected: ``unknown variant `MAYBE`, expected one of `PERMIT`, `DENY`, `DEFER`, `LEARNED` ``. ⚠️ But the daemon keeps running (F-5). |
| E5 | Replay a Claude-shaped `PreToolUse` straight into `isonapse-hook` | ✅ refused *before policy*: "did not recognize this caller as a governed host" (`preparation-refused`). Spoofing a host is not trivial. |
| E6 | Witness tamper drills on a copy (`witness verify --db`) | ✅ 6/6 detected (table below) |
| E7 | Gemini CLI hook semantics, read from source and pinned by tests | fail-open on exit 1 and timeouts; exact input rewrite; native ask; no tool-call id (see the adapter README) |

**E6: witness chain drills** (real chain of 8 receipts written by the daemon):

| Attack on the copied `witness.db` | Verifier |
| --- | --- |
| baseline, untouched | `VALID, anchored` |
| `decision` PERMIT→DENY on receipt 4 | `INVALID: Chain integrity violation at sequence 4` |
| rewrite `description` on receipt 4 | `INVALID … sequence 4` |
| delete receipt 5 | `INVALID … sequence 5` |
| delete the last receipt | `INVALID … sequence 8` |
| verify with a different Ed25519 key | `INVALID: head key e1bfa69c… does not match the supplied identity key` |
| truncate 6..8 **and** delete the signed head | `INVALID … sequence 0` |

Every drill was caught. The remaining gap is the threat the README already names: a process running
as the *same user* can read `~/.isonapse/identity/signing_key.pem` (owner-only, but the same owner)
and re-sign a shorter history. Local evidence alone cannot defeat that. **Anchoring outside the
machine can**, and that is what the policy guard's `evidence` check does. Its tests show that a
rollback to a valid older chain, and a chain re-keyed from scratch, are both caught.

---

## 2. Findings and proposals

Severity is my judgement of impact on adoption or safety. "How" is a concrete change, not a wish.

### F-1 · `install.sh` fails when an unrelated `GITHUB_TOKEN` is in the environment *(adoption: high)*
**What:** On the public `main` channel the installer still sends `GITHUB_TOKEN` if one is set
(`install.sh` L2162). A token that is expired, revoked or narrowly scoped turns an anonymous
install into `rejected authentication (HTTP 403)`. CI and devcontainers routinely carry such tokens.
**Why it matters:** this is the first command a new user runs.
**How:** for `main`, never send the token. Or retry anonymously on 401/403 and print one line
saying so.

### F-2 · Startup hard-depends on huggingface.co *(adoption: high in enterprises)*
**What:** `hook init` must fetch `all-MiniLM-L6-v2` (90.9 MB) from Hugging Face before the
control plane will start. The only pinned source in the binary is `https://huggingface.co/`. On a
network that blocks HF (common in corporate egress), init fails with
`failed to download … from every pinned source`.
**How:** publish the pinned model files as release assets beside the binaries. They are already
SHA-pinned, so the source does not matter for integrity. Also add
`isonapse hook intel import <dir>` for air-gapped installs.

### F-3 · `hook init` refuses a pre-seeded data root *(adoption: medium)*
**What:** Copying a known-good `models/` directory into a fresh `~/.isonapse` makes init refuse
with "neither initialized nor an exact Isonapse bootstrap scaffold". Placing binaries manually in
`~/.isonapse/bin`, the documented installer location, triggers the same refusal.
**Why it matters:** CI caches and golden images cannot skip the download, which compounds F-2.
**How:** let init accept and verify a `models/` subtree against the pins, the same check startup
already runs.

### F-4 · Running as root fails late and confusingly *(adoption: medium)*
**What:** As uid 0, `hook start` waits the full 45 s and reports "did not start", even though the
log shows `Control plane listening` within about 1 s. `hook status` and `hook mode` then fail with
"elevated CLI is missing its authenticated operator uid".
**Why it matters:** Docker, devcontainers and many CI images run as root. The refusal may well be
intended, but the error points people the wrong way.
**How:** check uid first and fail fast: *"Isonapse must run as your normal user (uid 0 detected).
See docs/…"*.

### F-5 · A broken policy is a WARN, and the daemon keeps serving *(safety: high)*
**What:** With an invalid `policy.lua`, the control plane logs `WARN Failed to load policy …` and
keeps running and listening. From outside I could not see which rules apply after that, and
`hook status` (which needs the CLI) does not flag it.
**Why it matters:** a typo in a project policy should never silently become weaker enforcement.
**How:** (a) refuse to start, or keep the last good policy and say so loudly in `status`, `doctor`
and the agent-visible message. (b) Add an offline `isonapse hook policy check <file>`. My
policy-guard `load` command does this today by booting the real engine.

### F-6 · Same-user evidence needs an external anchor *(safety: medium, by design)*
**What:** The chain is strong (E6), but the signing key lives with the user the agent runs as.
**How:** add `witness export --head-only` producing a small signed head, so CI, a ticket or a
transparency log can anchor it. The policy guard's `evidence` check shows the consumer side of that
design working.

### F-7 · Static command analysis cannot see inside scripts *(safety: known limit)*
**What:** `sh scripts/setup.sh` is analysed as `sh`. A `curl` inside the script is invisible. This
is vector 5 in the injection demo, and the README says it plainly ("not an OS sandbox").
**How (two layers):**
1. **Policy:** taint-aware DEFER. After the agent has *read* a file that matches injection
   detectors, or any repo file it did not author, running a repo-local script requires a human. The
   engine already has injection detectors and a learned baseline; this connects them.
2. **Runtime:** for Bash on Linux, an opt-in network namespace or seccomp egress filter around the
   tool process. "Not an OS sandbox" stays true for files, while network egress, the exfil path,
   gets closed.

### F-8 · Gemini CLI is a natural next host *(opportunity)*
Gemini 0.64 hooks support exact input rewrite and a native ask, which is more than the Codex
reference. The adapter is in `gemini-cli-adapter/`. One host-side gap matters for every
hook-command host: **Gemini fails open on exit 1 and timeouts**. Upstreaming a
`"failClosed": true` hook option to Gemini would remove that whole class of risk; the same applies
to Codex.

### F-9 · Smaller things I hit
* There is no `policy validate`. `explain` and `policy show` need a running daemon (see F-5b).
* `isonapse-hook --help` answers with an `ISONAPSE STOP` JSON rather than usage text.
* `witness query` has `--json`, but its schema isn't documented. A one-page reference would let
  tools like mine parse it without guessing.

---

## 3. Review of the public repository

Details and patches are in [`upstream-contributions/`](upstream-contributions/README.md). In short:

* **Conformance suite:** five deliberately wrong adapters passed it, including ones that accept an
  unknown decision, accept a missing `protocolVersion`, or leak a withheld result. Patch 1 adds
  three fixtures and an exact-argv check, and the suite then fails all five.
* **Test suites:** both packages' suites fail as root, which is common in CI. Patch 2 fixes this.
* **Python version check:** it could escape the outcome contract. Patch 3 fixes this.
* **Docs:** I found 15 documentation and example inconsistencies. Patch 4 fixes the five that are
  unambiguous; the rest need maintainer semantics.
* **Security:** one issue in a reference adapter was **reported privately** per `SECURITY.md`, with
  a fix and a red-to-green regression test.

## 4. What I would build next, in priority order

1. **Fix F-1, F-4 and F-5.** They are small changes with high adoption and safety leverage.
2. **Signed-head export plus the anchor Action (F-6)**, packaged as an official GitHub Action.
   "Prove what your agents did" becomes a one-line CI step, a strong story for Community Edition.
3. **Upstream the Gemini adapter** as `reference/gemini/` after a live receipt test on macOS.
4. **Taint-aware DEFER (F-7.1)**, measured with the injection harness. It already scores runs from
   ground truth, so it can report how many attacks get through before and after the change.
