"""F.1 DO-side unit tests: deletion re-drive classification and secret handling.

These tests do NOT require the live integration harness. The pure classifier is imported
directly; do_chain.redrive_deletion_request is tested with its heavy dependencies
(web3-backed do_config, do_vaultmesh, do_hex, do_log) replaced by lightweight fakes so the
secret-handling contract can be verified without a chain.

Run:  python3 -m pytest App/DO/core/test_deletion_redrive.py -v
"""

import sys
import types
import importlib
from pathlib import Path

import do_deletion_redrive as DR  # imported via conftest-less sys.path shim below


# --- make `import do_deletion_redrive` work when run from the repo root or the dir -------
_CORE_DIR = Path(__file__).resolve().parent
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
DR = importlib.import_module("do_deletion_redrive")


# ============================ pure classifier tests ====================================

def test_accepted_queued_response_causes_another_redrive():
    resp = {"ok": True, "accepted": True, "declared": False, "retryable": True,
            "pending": True, "phase": "accepted_queued"}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


def test_accepted_without_retryable_flag_still_continues():
    # accepted + not declared, even if retryable flag omitted, must keep re-driving.
    resp = {"ok": True, "accepted": True, "declared": False, "phase": "accepted_queued"}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


def test_declared_pending_stops_secret_redrive_but_not_terminal():
    resp = {"ok": True, "accepted": True, "declared": True, "phase": "declared_pending"}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_DECLARED  # stop secret re-drive; keep polling


def test_chain_declared_overrides_and_stops_redrive():
    # Even if the VK response looks queued, authoritative chain-declared wins.
    resp = {"ok": True, "accepted": True, "declared": False, "phase": "accepted_queued"}
    decision, _ = DR.classify_redrive(resp, {"declared": True})
    assert decision == DR.REDRIVE_DECLARED


def test_confirmed_completes_via_vk_response():
    resp = {"ok": True, "confirmed": True, "phase": "confirmed"}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONFIRMED


def test_confirmed_completes_via_chain_status():
    decision, _ = DR.classify_redrive({"accepted": True}, {"ok": True})
    assert decision == DR.REDRIVE_CONFIRMED


def test_transport_timeout_or_malformed_is_retryable_not_terminal():
    for resp in (None, {}, "garbage", 123):
        decision, _ = DR.classify_redrive(resp, {})
        assert decision == DR.REDRIVE_CONTINUE, f"resp={resp!r} must be retryable"


def test_busy_is_retryable_not_terminal():
    resp = {"ok": False, "busy": True, "retryAfterSeconds": 5}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


def test_temporary_vk_error_without_terminal_marker_is_retryable():
    # ok False with an error but explicitly retryable -> transient, keep going.
    resp = {"ok": False, "retryable": True, "error": "temporary RPC failure"}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


def test_ambiguous_non_ok_without_error_is_retryable():
    resp = {"ok": False}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


# Finding 2: TERMINAL requires an EXPLICIT permanent-rejection marker (terminal=true).
def test_generic_internal_error_without_terminal_flag_is_retryable():
    resp = {"ok": False, "error": "internal error"}  # no retryable field, no terminal flag
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


def test_unknown_error_code_without_terminal_flag_is_retryable():
    resp = {"ok": False, "error": "E_SOMETHING_NEW", "code": 599}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


def test_ok_false_retryable_absent_with_error_but_no_terminal_is_retryable():
    # Exactly the reviewer's concern: a responder that omitted `retryable` and set only an
    # error must NOT be treated as permanent.
    resp = {"ok": False, "error": "invalid deletion authorization secret"}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


def test_explicit_terminal_flag_is_terminal():
    resp = {"ok": False, "terminal": True, "error": "invalid deletion authorization secret"}
    decision, summary = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_TERMINAL
    assert "rejected" in summary.lower()


def test_terminal_flag_requires_ok_false():
    # terminal without ok False is not a coherent permanent rejection -> retry.
    resp = {"terminal": True}
    decision, _ = DR.classify_redrive(resp, {})
    assert decision == DR.REDRIVE_CONTINUE


# Finding 4 (per-item action planner): DECLARED/TERMINAL/CONTINUE/CONFIRMED mappings.
def test_plan_action_continue_preserves_entry_and_keeps_redriving():
    resp = {"ok": True, "accepted": True, "declared": False, "retryable": True}
    action, redrive_again = DR.plan_reconcile_action({}, resp)
    assert action == DR.ACTION_PENDING and redrive_again is True


def test_plan_action_declared_stops_secret_redrive_but_keeps_polling():
    resp = {"ok": True, "declared": True, "phase": "declared_pending"}
    action, redrive_again = DR.plan_reconcile_action({}, resp)
    assert action == DR.ACTION_PENDING and redrive_again is False


def test_plan_action_terminal_fails_without_dispute():
    resp = {"ok": False, "terminal": True, "error": "invalid secret"}
    action, redrive_again = DR.plan_reconcile_action({}, resp)
    assert action == DR.ACTION_FAILED and redrive_again is False


def test_plan_action_confirmed_resolves():
    action, redrive_again = DR.plan_reconcile_action({"ok": True}, {"accepted": True})
    assert action == DR.ACTION_CONFIRMED and redrive_again is False


def test_classifier_never_returns_a_secret():
    # The classifier never receives the secret; guard that no summary echoes one.
    secret = "0x" + "ab" * 32
    for resp in ({"ok": False, "retryable": False, "error": "x"}, {"accepted": True}, {}):
        _, summary = DR.classify_redrive(resp, {})
        assert secret not in summary


# ================= redrive_deletion_request: secret passed, never logged ================

def _install_fake_do_chain_deps(recorded):
    """Inject lightweight fakes for do_chain's heavy imports so it can be imported here."""
    # Fake web3 so do_config imports.
    web3_mod = types.ModuleType("web3")
    web3_mod.Web3 = object
    sys.modules.setdefault("web3", web3_mod)

    pkg = "do_chain_test_pkg"
    if pkg not in sys.modules:
        pkgmod = types.ModuleType(pkg)
        pkgmod.__path__ = []  # namespace-ish package
        sys.modules[pkg] = pkgmod

    # Fake do_config (C): only the attributes redrive_deletion_request touches.
    C = types.ModuleType(pkg + ".do_config")
    C.VAULTMESH_CMD = "vaultmesh"
    sys.modules[pkg + ".do_config"] = C

    # Fake do_vaultmesh (VM): records the exact command it was asked to run.
    VM = types.ModuleType(pkg + ".do_vaultmesh")

    def _run(cmd):
        recorded["cmd"] = list(cmd)
        return recorded["vk_output"]
    VM.run_vaultmesh_cmd = _run

    # A deletion is signed by the data owner on every attempt, so the re-drive
    # asks for one each time round. Signed fresh rather than once: this loop can
    # run for a long time, and a reused signature would go stale and the
    # deletion would never complete.
    def _delete_auth(commitment_hash):
        recorded["signedCommitments"] = recorded.get("signedCommitments", [])
        recorded["signedCommitments"].append(commitment_hash)
        return "0xD0" + "11" * 19, 1788288577, "0x" + "ab" * 65
    VM.build_vaultmesh_delete_auth = _delete_auth
    sys.modules[pkg + ".do_vaultmesh"] = VM

    # Fake do_log (L): records every logged message so we can assert the secret is absent.
    L = types.ModuleType(pkg + ".do_log")

    def _log(msg, *a, **k):
        recorded["logs"].append(str(msg))
    L.log = _log
    L.set_status = lambda *a, **k: None
    L.show_error = lambda *a, **k: None
    sys.modules[pkg + ".do_log"] = L

    # Fake do_hex (HX): normalize_hex just needs to not raise for a valid 32-byte hex.
    HX = types.ModuleType(pkg + ".do_hex")

    def _normalize_hex(value, expected_bytes=None, field=None):
        return value
    HX.normalize_hex = _normalize_hex
    sys.modules[pkg + ".do_hex"] = HX
    return C, VM, L, HX


def _load_redrive_function(recorded):
    """Import just the redrive_deletion_request source under the fake package."""
    C, VM, L, HX = _install_fake_do_chain_deps(recorded)
    # Execute redrive_deletion_request's source with the fakes bound, avoiding the full
    # do_chain import (which pulls in the entire chain stack).
    src = (Path(__file__).resolve().parent / "do_chain.py").read_text()
    # Extract the function definition block.
    start = src.index("def redrive_deletion_request(")
    end = src.index("\ndef request_file_deletion(")
    func_src = src[start:end]
    glb = {"C": C, "HX": HX, "json": __import__("json")}
    # `from . import do_vaultmesh as VM` inside the function resolves via our fake pkg.
    glb["__package__"] = "do_chain_test_pkg"
    ns = {}
    exec(compile(func_src, "redrive_src", "exec"), glb, ns)
    return ns["redrive_deletion_request"]


def test_redrive_passes_secret_to_command_but_never_logs_it():
    secret = "0x" + "cd" * 32
    recorded = {"logs": [], "cmd": None,
                "vk_output": '{"ok": true, "accepted": true, "declared": false, "retryable": true}'}
    fn = _load_redrive_function(recorded)
    resp = fn("peer-abc", "0x" + "11" * 32, secret)

    # The secret must be present in the command handed to the VK runner...
    assert recorded["cmd"] is not None
    assert "--deletion-auth-secret" in recorded["cmd"]
    assert secret in recorded["cmd"]
    # ...and must NOT appear in any log line.
    for line in recorded["logs"]:
        assert secret not in line, "secret leaked into a log line"
    # Structured response passes through for the classifier.
    assert isinstance(resp, dict) and resp.get("accepted") is True


def test_redrive_transport_failure_returns_empty_dict_and_is_retryable():
    recorded = {"logs": [], "cmd": None, "vk_output": "not-json-at-all"}
    fn = _load_redrive_function(recorded)
    resp = fn("peer-abc", "0x" + "11" * 32, "0x" + "cd" * 32)
    assert resp == {}
    # And the classifier treats an empty response as retryable, never terminal.
    assert DR.classify_redrive(resp, {})[0] == DR.REDRIVE_CONTINUE
