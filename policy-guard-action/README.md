# isonapse-policy-guard: a review gate for agent governance

Isonapse lets a team commit `.isonapse/policy.lua` so that agent rules travel with the code. This
also means **a pull request can quietly give every agent on the team more power**. One changed line
(`DEFER` → `PERMIT` on `curl`, or a new domain in an allowlist) can open an exfiltration path, and
reviewers tend to skim Lua.

This GitHub Action (plus a CLI you can run locally) closes that gap with three checks:

| Check | What it does | Why it matters |
| --- | --- | --- |
| **`diff`** | Evaluates the base and head policy in a **sandboxed Lua runtime** (no `io`/`os`/`require`/`load`), then classifies each change as 🔓 widening, 🔒 tightening, 👀 needs review (edits to runtime `check_action` logic) or ℹ️ no effect. Writes a table to the PR job summary. **Fails on widening** unless the PR carries the `isonapse-widening-approved` label. | Turns a Lua diff into a security diff a reviewer can't miss. |
| **`load`** | Boots the **real Isonapse engine** in a throw-away home against the policy, and fails if the engine refuses it. | The daemon only *logs a WARN* on a broken policy and keeps running (finding F-5). Without this check, a typo can merge. |
| **`evidence`** | Verifies an exported witness DB with the official offline verifier, then compares it with an **append-only anchor log** in the repo. | A signed chain proves internal consistency, but someone who controls the machine also controls the signing key. Anchoring catches a **rolled-back** or **re-keyed** chain that would still verify on its own. |

## Sample output (real, produced by the tests)

PR that "just tweaks a few rules" in the exfil-firewall policy:

```markdown
| Effect | Area | Change |
| --- | --- | --- |
| 🔓 widening | actions | `tool:Bash:curl`: DEFER -> PERMIT |
| 🔓 widening | allowed_domains | `tool:WebFetch` may now reach `collector.attacker.example` |
| 🔓 widening | blocked_capabilities | blocked capability removed for `*`: `tool:Bash:nc` |
| 🔓 widening | max_payload_size | `cap:http-request`: 65536 -> 10485760 |
| 👀 needs review | check_action | runtime `check_action` source changed (cannot be diffed semantically) |
| ℹ️ no effect | allowed_domains | `webhook.site` added to the allowlist but still blocked by `blocked_domains` |
```

Evidence that was rolled back to an older, perfectly valid chain:

```
✅ Signature chain VALID: receipts 1..8, key `16cab578910e8b48`
❌ Anchor check failed
- chain is SHORTER than the last anchor (8 < 9): history was rolled back
```

## Tests: 26 passing, real engine and real chains

```sh
pip install lupa pytest
# optional: point at a checkout of Isonapse/isonapse-public to also run the 14 official examples
ISONAPSE_PUBLIC_REPO=../../isonapse-public python3 -m pytest -q test_isonapse_ci.py
```

* All **14 official example policies** from `examples/policies` evaluate in the sandbox, so it
  matches the engine's Lua surface.
* The sandbox refuses `os.execute`, `io.open` and `require`.
* The widening, review, allowlist-removal, tightening-only and new-file cases are each covered.
* **Real engine:** the firewall policy is accepted, and a `decision = "MAYBE"` typo is rejected with
  the engine's own error.
* **Real witness chains:** the `fixtures/` were produced by a live Isonapse 0.3.0-beta daemon. The
  tests cover valid chain → anchor → extend; **rollback to a valid older chain is caught**; a
  **re-keyed chain is caught**; and an edited receipt fails the signature check.

## Use

See `example-workflow.yml`. Run it on `ubuntu-24.04` (Isonapse ships x86_64 Linux builds). On
`push` to `main` it appends an anchor and commits it, so history stays append-only and reviewable.

Locally:

```sh
python3 isonapse_ci.py diff --base old.lua --head .isonapse/policy.lua
python3 isonapse_ci.py load .isonapse/policy.lua
python3 isonapse_ci.py evidence --db witness.db --identity ./identity --anchors anchors.jsonl --write-anchor
```
