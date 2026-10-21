#!/usr/bin/env python3
"""isonapse-ci: review gates for Isonapse policies and evidence in pull requests.

Three checks, each usable alone:

  diff     Evaluate the base and head versions of a Lua policy in a sandboxed
           Lua runtime (no io/os/require) and classify every change as
           WIDENING (the agent may now do more) or TIGHTENING. Widening fails
           the check unless explicitly approved (e.g. a PR label).
  load     Boot the real Isonapse control plane against the policy in a
           throw-away home and fail if the engine refuses it. (The daemon
           itself only logs a WARN and keeps running on a bad policy.)
  evidence Verify an exported witness database offline with the official CLI
           and compare it with an append-only anchor log committed to the
           repo, so a rolled-back or re-keyed chain is caught even by someone
           who controls the machine that produced it.

Apache-2.0. Not an official Isonapse component.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

DECISION_RANK = {"DENY": 0, "DEFER": 1, "LEARNED": 2, "PERMIT": 3, None: 4}  # higher = more permissive; None = no rule


# ---------------------------------------------------------------------------
# Sandboxed Lua evaluation
# ---------------------------------------------------------------------------

def load_policy(source: str) -> dict:
    """Evaluate a policy chunk with no io/os/require/load and return it as Python data."""
    from lupa import LuaRuntime  # lupa is the only dependency

    lua = LuaRuntime(register_eval=False, unpack_returned_tuples=True)
    # Like the engine's sandbox: pure-computation globals only. The policy
    # chunk gets a fresh environment with no io, os, require, load or debug.
    run = lua.eval("""
      function(src)
        local env = {
          string = string, table = table, math = math, utf8 = utf8,
          pairs = pairs, ipairs = ipairs, next = next, select = select, type = type,
          tostring = tostring, tonumber = tonumber, error = error, assert = assert,
          pcall = pcall, setmetatable = setmetatable, getmetatable = getmetatable,
          rawget = rawget, rawset = rawset, rawequal = rawequal, unpack = table.unpack,
          isonapse = { config = { get = function() return nil end } },
        }
        local f, err = load(src, '=policy', 't', env)
        if not f then error(err, 0) end
        local result = f()
        return result, env.check_action ~= nil
      end
    """)
    result, has_check_action = run(source)
    data = _to_py(result)
    if not isinstance(data, dict):
        raise ValueError("policy chunk must return a table")
    data["__has_check_action__"] = bool(has_check_action)
    return data


def _to_py(value):
    if hasattr(value, "items") and type(value).__name__ == "_LuaTable":
        items = list(value.items())
        keys = [k for k, _ in items]
        if keys and all(isinstance(k, int) for k in keys) and sorted(keys) == list(range(1, len(keys) + 1)):
            return [_to_py(v) for _, v in sorted(items)]
        return {str(k): _to_py(v) for k, v in items}
    if type(value).__name__ == "_LuaFunction":
        return "<function>"
    return value


# ---------------------------------------------------------------------------
# Semantic diff
# ---------------------------------------------------------------------------

@dataclass
class Change:
    kind: str  # "widening" | "tightening" | "review" | "note"
    area: str
    detail: str


@dataclass
class Diff:
    changes: list[Change] = field(default_factory=list)

    def add(self, kind: str, area: str, detail: str) -> None:
        self.changes.append(Change(kind, area, detail))

    @property
    def widening(self) -> list[Change]:
        return [c for c in self.changes if c.kind in ("widening", "review")]


def _as_map_of_lists(value) -> dict[str, set[str]]:
    if not isinstance(value, dict):
        return {}
    out = {}
    for key, items in value.items():
        out[key] = set(items if isinstance(items, list) else [])
    return out


def diff_policies(base: dict, head: dict) -> Diff:
    d = Diff()

    # actions: decision ladder per capability
    ba, ha = base.get("actions") or {}, head.get("actions") or {}
    for cap in sorted(set(ba) | set(ha)):
        b = (ba.get(cap) or {}).get("decision") if cap in ba else None
        h = (ha.get(cap) or {}).get("decision") if cap in ha else None
        if b == h:
            bs, hs = set((ba.get(cap) or {}).get("allowed_secrets") or []), set((ha.get(cap) or {}).get("allowed_secrets") or [])
            if hs - bs:
                d.add("widening", "actions", f"`{cap}` may now receive secrets {sorted(hs - bs)}")
            bp, hp = set((ba.get(cap) or {}).get("pii_allowlist") or []), set((ha.get(cap) or {}).get("pii_allowlist") or [])
            if hp - bp:
                d.add("widening", "actions", f"`{cap}` PII allowlist grew by {sorted(hp - bp)}")
            if (ba.get(cap) or {}).get("trust") != (ha.get(cap) or {}).get("trust") and (ha.get(cap) or {}).get("trust") == "local":
                d.add("widening", "actions", f"`{cap}` moved to trust zone `local` (sees plaintext PII)")
            continue
        if DECISION_RANK[h] > DECISION_RANK[b]:
            d.add("widening", "actions", f"`{cap}`: {b or '(no rule)'} -> {h or '(no rule, default applies)'}")
        else:
            d.add("tightening", "actions", f"`{cap}`: {b or '(no rule)'} -> {h}")

    # list-valued fields where an added entry restricts
    for fieldname, label in (("blocked_capabilities", "blocked capability"), ("blocked_file_patterns", "blocked file pattern"), ("blocked_domains", "blocked domain")):
        bm, hm = _as_map_of_lists(base.get(fieldname)), _as_map_of_lists(head.get(fieldname))
        for key in sorted(set(bm) | set(hm)):
            removed, added = bm.get(key, set()) - hm.get(key, set()), hm.get(key, set()) - bm.get(key, set())
            for item in sorted(removed):
                d.add("widening", fieldname, f"{label} removed for `{key}`: `{item}`")
            for item in sorted(added):
                d.add("tightening", fieldname, f"{label} added for `{key}`: `{item}`")

    # allowed_domains: an added entry widens; a list that disappears entirely
    # means "no restriction" for that capability, the biggest widening of all.
    bm, hm = _as_map_of_lists(base.get("allowed_domains")), _as_map_of_lists(head.get("allowed_domains"))
    for key in sorted(set(bm) | set(hm)):
        if key in bm and bm[key] and not hm.get(key):
            d.add("widening", "allowed_domains", f"egress allowlist for `{key}` removed: ANY domain is now reachable")
            continue
        if not bm.get(key) and hm.get(key):
            d.add("tightening", "allowed_domains", f"`{key}` egress limited to {len(hm[key])} allowlisted domain(s) (was unrestricted)")
            continue
        still_blocked = _as_map_of_lists(head.get("blocked_domains")).get(key, set())
        for item in sorted(hm.get(key, set()) - bm.get(key, set())):
            if item in still_blocked:
                d.add("note", "allowed_domains", f"`{item}` added to the `{key}` allowlist but still blocked by `blocked_domains` (no effect; likely a mistake)")
            else:
                d.add("widening", "allowed_domains", f"`{key}` may now reach `{item}`")
        for item in sorted(bm.get(key, set()) - hm.get(key, set())):
            d.add("tightening", "allowed_domains", f"`{key}` may no longer reach `{item}`")

    # numeric ceilings: bigger (or gone) widens
    for fieldname in ("max_payload_size",):
        bm, hm = base.get(fieldname) or {}, head.get(fieldname) or {}
        for key in sorted(set(bm) | set(hm)):
            b, h = bm.get(key), hm.get(key)
            if b is not None and (h is None or h > b):
                d.add("widening", fieldname, f"`{key}`: {b} -> {h if h is not None else 'unlimited'}")
            elif h is not None and (b is None or h < b):
                d.add("tightening", fieldname, f"`{key}`: {b if b is not None else 'unlimited'} -> {h}")
    br, hr = base.get("rate_limits") or {}, head.get("rate_limits") or {}
    for key in sorted(set(br) | set(hr)):
        for window in ("per_minute", "per_hour", "per_day"):
            b, h = (br.get(key) or {}).get(window), (hr.get(key) or {}).get(window)
            if b is not None and (h is None or h > b):
                d.add("widening", "rate_limits", f"`{key}` {window}: {b} -> {h if h is not None else 'unlimited'}")
            elif h is not None and (b is None or h < b):
                d.add("tightening", "rate_limits", f"`{key}` {window}: {b if b is not None else 'unlimited'} -> {h}")

    # runtime logic cannot be diffed semantically: any change needs a human
    if base.get("__has_check_action__") != head.get("__has_check_action__"):
        d.add("review", "check_action", "runtime `check_action` added or removed")
    return d


def render_markdown(d: Diff, path: str, check_action_changed: bool) -> str:
    if check_action_changed and not any(c.area == "check_action" for c in d.changes):
        d.add("review", "check_action", "runtime `check_action` source changed (cannot be diffed semantically)")
    lines = [f"### Isonapse policy review: `{path}`", ""]
    if not d.changes:
        lines.append("No semantic change.")
        return "\n".join(lines)
    icon = {"widening": "🔓 widening", "tightening": "🔒 tightening", "review": "👀 needs review", "note": "ℹ️ no effect"}
    lines += ["| Effect | Area | Change |", "| --- | --- | --- |"]
    for c in sorted(d.changes, key=lambda c: ("widening review tightening note".split().index(c.kind), c.area)):
        lines.append(f"| {icon[c.kind]} | {c.area} | {c.detail} |")
    lines.append("")
    lines.append(f"**{len(d.widening)}** change(s) give agents more power; **{sum(c.kind == 'tightening' for c in d.changes)}** restrict them.")
    return "\n".join(lines)


def _check_action_source(src: str) -> str:
    m = re.search(r"function\s+check_action\b.*?\nend\b", src, re.S)
    return m.group(0) if m else ""


def cmd_diff(args) -> int:
    base_src = Path(args.base).read_text() if args.base and Path(args.base).exists() else "return {}"
    head_src = Path(args.head).read_text()
    base, head = load_policy(base_src), load_policy(head_src)
    d = diff_policies(base, head)
    md = render_markdown(d, args.label or args.head, _check_action_source(base_src) != _check_action_source(head_src))
    print(md)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as fh:
            fh.write(md + "\n\n")
    if args.json:
        Path(args.json).write_text(json.dumps([c.__dict__ for c in d.changes], indent=2))
    if d.widening and not args.allow_widening:
        print(f"\n::error::{len(d.widening)} policy change(s) widen what agents may do. Add the approval label after review.", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# Real-engine load check
# ---------------------------------------------------------------------------

def cmd_load(args) -> int:
    isonapse = shutil.which("isonapse", path=args.bin_dir) or shutil.which("isonapse")
    if not isonapse:
        print("::error::isonapse CLI not found", file=sys.stderr)
        return 2
    policy = Path(args.policy).resolve()
    with tempfile.TemporaryDirectory(prefix="isonapse-ci-") as tmp:
        home = Path(tmp)
        env = {**os.environ, "HOME": str(home)}
        # Note: `hook init` refuses a pre-seeded data root, so the 90 MB embedding
        # model cannot be restored from a CI cache before init (finding F-3).
        subprocess.run([isonapse, "hook", "init"], env=env, check=False, capture_output=True, timeout=600)
        target = home / ".isonapse" / "policy" / "policy.lua"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(policy, target)
        log = home / "serve.log"
        with open(log, "w") as fh:
            proc = subprocess.Popen([isonapse, "hook", "serve"], env=env, stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.time() + args.timeout
        verdict = None
        while time.time() < deadline and verdict is None:
            text = log.read_text(errors="replace")
            if "Failed to load policy" in text:
                verdict = False
            elif "Loaded policy" in text:
                verdict = True
            elif proc.poll() is not None:
                break
            time.sleep(0.25)
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        proc.wait(timeout=30)
        text = log.read_text(errors="replace")
        if verdict:
            print(f"Isonapse engine loaded {args.policy}")
            return 0
        err = next((line for line in text.splitlines() if "Failed to load policy" in line), text[-2000:])
        print(f"::error file={args.policy}::Isonapse engine refused this policy: {err.split('error=', 1)[-1]}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Evidence verification + anchoring
# ---------------------------------------------------------------------------

def _verify(isonapse: str, db: Path, identity: Path) -> tuple[bool, int, int, str]:
    out = subprocess.run([isonapse, "hook", "witness", "verify", "--db", str(db), "--identity", str(identity)], capture_output=True, text=True, timeout=300)
    text = out.stdout + out.stderr
    m = re.search(r"Live sequence range:\s+(\d+)\.\.(\d+)", text)
    first, last = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    return out.returncode == 0 and "VALID" in text and "INVALID" not in text, first, last, text


def _key_fingerprint(identity: Path) -> str:
    return hashlib.sha256((identity / "verifying_key.pem").read_bytes()).hexdigest()


def _receipt_digest(db: Path, upto: int) -> str:
    """Hash of the entry_hash column up to `upto`: binds an anchor to exact history."""
    import sqlite3

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        h = hashlib.sha256()
        for (entry_hash,) in con.execute("select entry_hash from witness_log where seq_id <= ? order by seq_id", (upto,)):
            h.update(bytes(entry_hash))
        return h.hexdigest()
    finally:
        con.close()


def cmd_evidence(args) -> int:
    isonapse = shutil.which("isonapse", path=args.bin_dir) or shutil.which("isonapse")
    if not isonapse:
        print("::error::isonapse CLI not found", file=sys.stderr)
        return 2
    db, identity, anchors = Path(args.db), Path(args.identity), Path(args.anchors)
    ok, first, last, text = _verify(isonapse, db, identity)
    lines = [f"### Isonapse evidence: `{db}`", ""]
    if not ok:
        lines.append(f"❌ **Signature chain INVALID**\n\n```\n{text.strip()[-1500:]}\n```")
        _emit(lines)
        return 1
    fp = _key_fingerprint(identity)
    digest = _receipt_digest(db, last)
    history = [json.loads(line) for line in anchors.read_text().splitlines() if line.strip()] if anchors.exists() else []
    problems = []
    if history:
        prev = history[-1]
        if prev["key_sha256"] != fp:
            problems.append(f"signing key changed ({prev['key_sha256'][:12]} -> {fp[:12]}): a re-keyed chain can rewrite history")
        if last < prev["last_seq"]:
            problems.append(f"chain is SHORTER than the last anchor ({last} < {prev['last_seq']}): history was rolled back")
        elif _receipt_digest(db, prev["last_seq"]) != prev["prefix_sha256"]:
            problems.append(f"receipts 1..{prev['last_seq']} differ from the anchored history: history was rewritten")
    lines.append(f"✅ Signature chain VALID: receipts {first}..{last}, key `{fp[:16]}`")
    if problems:
        lines += ["", "❌ **Anchor check failed**"] + [f"- {p}" for p in problems]
        _emit(lines)
        return 1
    lines.append(f"✅ Consistent with {len(history)} prior anchor(s)" if history else "ℹ️ First anchor for this chain")
    if args.write_anchor:
        with open(anchors, "a") as fh:
            fh.write(json.dumps({"last_seq": last, "prefix_sha256": digest, "key_sha256": fp, "anchored_at": int(time.time())}) + "\n")
        lines.append(f"📌 Anchored receipts 1..{last} (`{digest[:16]}`) in `{anchors}`")
    _emit(lines)
    return 0


def _emit(lines: list[str]) -> None:
    md = "\n".join(lines)
    print(md)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as fh:
            fh.write(md + "\n\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="isonapse-ci", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff", help="classify policy changes as widening/tightening")
    d.add_argument("--base", help="policy before the change (missing file = empty policy)")
    d.add_argument("--head", required=True, help="policy after the change")
    d.add_argument("--label", help="display name")
    d.add_argument("--allow-widening", action="store_true", help="report but do not fail on widening (e.g. approved by label)")
    d.add_argument("--json", help="also write machine-readable changes here")
    d.set_defaults(fn=cmd_diff)
    ld = sub.add_parser("load", help="boot the real engine against a policy")
    ld.add_argument("policy")
    ld.add_argument("--bin-dir", help="directory containing the isonapse CLI")
    ld.add_argument("--timeout", type=float, default=90)
    ld.set_defaults(fn=cmd_load)
    ev = sub.add_parser("evidence", help="verify a witness DB and check it against the anchor log")
    ev.add_argument("--db", required=True)
    ev.add_argument("--identity", required=True, help="directory with verifying_key.pem")
    ev.add_argument("--anchors", default=".isonapse/evidence/anchors.jsonl")
    ev.add_argument("--write-anchor", action="store_true", help="append a new anchor after a successful check")
    ev.add_argument("--bin-dir")
    ev.set_defaults(fn=cmd_evidence)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
