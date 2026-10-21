# Isonapse: three builds, a repo review and an assessment

Exercise for Isonapse ("build a small use case on the daemon; share results, findings, and what
I'd change"). I built three things, then reviewed the repository itself. Each piece attacks a different part of the problem: which agents
are governed, what the policy stops, and whether anyone can trust the evidence afterwards.

| | Build | One line | Proof |
| --- | --- | --- | --- |
| 1 | [`gemini-cli-adapter/`](gemini-cli-adapter/) | Brings **Google Gemini CLI** under Isonapse via the Hook ADK. It turns out to be a richer host than the Codex reference (exact rewrite **and** native ask). | 15/15 e2e tests through **Gemini's own hook runner** and the real ADK transport |
| 2 | [`injection-firewall/`](injection-firewall/) | A Lua policy organised by attacker goal, plus a red-team harness: same agent, same poisoned repo, with and without Isonapse, scored from ground truth on disk. | Policy accepted by the **real engine**; harness ready for one-command runs |
| 3 | [`policy-guard-action/`](policy-guard-action/) | A GitHub Action that catches PRs **widening** agent powers, validates policies with the real engine, and detects **rolled-back or re-keyed** evidence. | 26/26 tests, with the real engine and real signed chains |
| 4 | [`upstream-contributions/`](upstream-contributions/) | A review of the repo shared: ADK (Python and TypeScript), conformance suite, reference adapters and every doc. **Four ready-to-apply patches**, plus one security issue reported privately. | Patches apply cleanly on `54c1d95`; all suites green; the conformance fix catches 5 wrong adapters that used to PASS |

**Assessment and findings → [REPORT.md](REPORT.md)**: nine product findings, each with what, why and how,
including six witness tamper drills (all detected) and four adoption blockers that are cheap to
fix.

## Run everything

```sh
# 1. Gemini adapter (Node 22+)
cd gemini-cli-adapter && npm install && npm test

# 2. Policy guard (Python 3.10+; isonapse CLI on PATH enables the real-engine tests)
cd policy-guard-action && pip install lupa pytest && python3 -m pytest -q

# 3. Injection red-team (macOS arm64 / Linux x86_64, Claude Code + Isonapse, normal user)
cd injection-firewall/harness && ./run-demo.sh baseline && ./run-demo.sh protected && ./run-demo.sh report
```

Licence: Apache-2.0 for my code. Isonapse binaries remain under their own EULA. The Gemini adapter
is "compatible with Isonapse Host Adapter Protocol v1", not an official component.
