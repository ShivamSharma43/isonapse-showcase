"""Tests for isonapse_ci. The `load` and `evidence` tests run the REAL Isonapse
CLI and REAL signed witness chains (fixtures/ were produced by a live daemon);
they are skipped only when the CLI is not installed."""
import os
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import isonapse_ci as ci  # noqa: E402

REPO = Path(os.environ.get("ISONAPSE_PUBLIC_REPO", HERE.parent.parent / "repo" / "isonapse"))
FIREWALL = HERE.parent / "injection-firewall" / "policy" / "exfil-firewall.lua"
FIX = HERE / "fixtures"
HAS_CLI = shutil.which("isonapse") is not None


# --- sandboxed evaluation ---------------------------------------------------

@pytest.mark.skipif(not (REPO / "examples" / "policies").exists(), reason="public repo checkout not present")
@pytest.mark.parametrize("path", sorted((REPO / "examples" / "policies").glob("**/*.lua")) if (REPO / "examples" / "policies").exists() else [], ids=lambda p: p.name)
def test_every_official_example_evaluates(path):
    data = ci.load_policy(path.read_text())
    assert isinstance(data.get("policy_version"), str)


def test_sandbox_has_no_os_or_io():
    with pytest.raises(Exception):
        ci.load_policy("os.execute('touch /tmp/pwned') return {}")
    with pytest.raises(Exception):
        ci.load_policy("io.open('/etc/passwd') return {}")
    with pytest.raises(Exception):
        ci.load_policy("require('socket') return {}")


# --- semantic diff ------------------------------------------------------------

def widened_firewall() -> str:
    src = FIREWALL.read_text()
    src = src.replace('["tool:Bash:curl"]    = ask(', '["tool:Bash:curl"]    = { decision = "PERMIT" } or ask(')
    src = src.replace('"tool:Bash:nc", "tool:Bash:ncat", ', '"tool:Bash:ncat", ')
    src = src.replace('"pkg.go.dev", "stackoverflow.com",', '"pkg.go.dev", "stackoverflow.com", "webhook.site", "collector.attacker.example",')
    src = src.replace('["cap:http-request"] = 65536', '["cap:http-request"] = 10485760')
    src = src.replace('return { decision = "DEFER", reason = "publishing or re-pointing remotes requires a human" }', 'return nil')
    return src


def test_widening_is_detected_and_explained():
    base, head = ci.load_policy(FIREWALL.read_text()), ci.load_policy(widened_firewall())
    d = ci.diff_policies(base, head)
    text = "\n".join(c.detail for c in d.widening)
    assert "`tool:Bash:curl`: DEFER -> PERMIT" in text
    assert "blocked capability removed for `*`: `tool:Bash:nc`" in text
    assert "`tool:WebFetch` may now reach `collector.attacker.example`" in text
    # webhook.site is also in blocked_domains, so allowing it changes nothing
    assert "webhook.site" not in text
    assert any("still blocked" in c.detail for c in d.changes)
    assert "`cap:http-request`: 65536 -> 10485760" in text


def test_check_action_edit_needs_review(tmp_path, capsys):
    (tmp_path / "base.lua").write_text(FIREWALL.read_text())
    (tmp_path / "head.lua").write_text(widened_firewall())
    assert ci.main(["diff", "--base", str(tmp_path / "base.lua"), "--head", str(tmp_path / "head.lua")]) == 1
    out = capsys.readouterr().out
    assert "needs review" in out and "check_action" in out
    assert ci.main(["diff", "--base", str(tmp_path / "base.lua"), "--head", str(tmp_path / "head.lua"), "--allow-widening"]) == 0


def test_removing_an_allowlist_is_the_biggest_widening():
    base = ci.load_policy('return { allowed_domains = { ["tool:WebFetch"] = { "github.com" } } }')
    head = ci.load_policy('return { }')
    [c] = ci.diff_policies(base, head).widening
    assert "ANY domain" in c.detail


def test_tightening_only_passes(tmp_path):
    (tmp_path / "base.lua").write_text('return { actions = { ["tool:Bash:curl"] = { decision = "PERMIT" } } }')
    (tmp_path / "head.lua").write_text('return { actions = { ["tool:Bash:curl"] = { decision = "DENY" } }, blocked_file_patterns = { ["tool:Read"] = { "**/.env" } } }')
    assert ci.main(["diff", "--base", str(tmp_path / "base.lua"), "--head", str(tmp_path / "head.lua")]) == 0


def test_new_restrictive_policy_only_asks_review_of_its_runtime_logic():
    d = ci.diff_policies(ci.load_policy("return {}"), ci.load_policy(FIREWALL.read_text()))
    assert [c.kind for c in d.widening] == ["review"]  # the new check_action, nothing else
    assert any("egress limited" in c.detail for c in d.changes)


# --- real engine ----------------------------------------------------------------

@pytest.mark.skipif(not HAS_CLI, reason="isonapse CLI not installed")
def test_real_engine_accepts_firewall():
    assert ci.main(["load", str(FIREWALL)]) == 0


@pytest.mark.skipif(not HAS_CLI, reason="isonapse CLI not installed")
def test_real_engine_rejects_typo(tmp_path, capsys):
    bad = tmp_path / "bad.lua"
    bad.write_text('return { actions = { ["tool:Bash:rm"] = { decision = "MAYBE" } } }')
    assert ci.main(["load", str(bad)]) == 1
    assert "unknown variant `MAYBE`" in capsys.readouterr().err


# --- evidence ---------------------------------------------------------------------

def _copy(name, tmp_path):
    dst = tmp_path / name
    shutil.copytree(FIX / name, dst)
    return dst


@pytest.mark.skipif(not HAS_CLI, reason="isonapse CLI not installed")
def test_valid_chain_is_anchored_then_extended(tmp_path):
    anchors = tmp_path / "anchors.jsonl"
    old, new = _copy("evidence-old", tmp_path), _copy("evidence-new", tmp_path)
    assert ci.main(["evidence", "--db", str(old / "witness.db"), "--identity", str(FIX / "identity"), "--anchors", str(anchors), "--write-anchor"]) == 0
    assert ci.main(["evidence", "--db", str(new / "witness.db"), "--identity", str(FIX / "identity"), "--anchors", str(anchors), "--write-anchor"]) == 0
    assert len(anchors.read_text().splitlines()) == 2


@pytest.mark.skipif(not HAS_CLI, reason="isonapse CLI not installed")
def test_rollback_to_a_valid_older_chain_is_caught(tmp_path, capsys):
    anchors = tmp_path / "anchors.jsonl"
    old, new = _copy("evidence-old", tmp_path), _copy("evidence-new", tmp_path)
    assert ci.main(["evidence", "--db", str(new / "witness.db"), "--identity", str(FIX / "identity"), "--anchors", str(anchors), "--write-anchor"]) == 0
    # The OLD snapshot is a perfectly valid signed chain on its own...
    assert ci._verify(shutil.which("isonapse"), old / "witness.db", FIX / "identity")[0]
    # ...but it is shorter than what we already anchored.
    assert ci.main(["evidence", "--db", str(old / "witness.db"), "--identity", str(FIX / "identity"), "--anchors", str(anchors)]) == 1
    assert "rolled back" in capsys.readouterr().out


@pytest.mark.skipif(not HAS_CLI, reason="isonapse CLI not installed")
def test_rekeyed_chain_is_caught(tmp_path, capsys):
    anchors = tmp_path / "anchors.jsonl"
    new, other = _copy("evidence-new", tmp_path), _copy("evidence-rekeyed", tmp_path)
    assert ci.main(["evidence", "--db", str(new / "witness.db"), "--identity", str(FIX / "identity"), "--anchors", str(anchors), "--write-anchor"]) == 0
    assert ci.main(["evidence", "--db", str(other / "witness.db"), "--identity", str(FIX / "identity-rekeyed"), "--anchors", str(anchors)]) == 1
    assert "signing key changed" in capsys.readouterr().out


@pytest.mark.skipif(not HAS_CLI, reason="isonapse CLI not installed")
def test_edited_receipt_fails_signature(tmp_path, capsys):
    new = _copy("evidence-new", tmp_path)
    con = sqlite3.connect(new / "witness.db")
    con.execute("update witness_log set decision='DENY' where seq_id=4")
    con.commit()
    con.close()
    assert ci.main(["evidence", "--db", str(new / "witness.db"), "--identity", str(FIX / "identity"), "--anchors", str(tmp_path / "a.jsonl")]) == 1
    assert "INVALID" in capsys.readouterr().out
