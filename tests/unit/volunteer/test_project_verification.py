from __future__ import annotations

from pathlib import Path

import pytest

from bernstein.core.volunteer.project_verification import (
    GateObservation,
    ProjectVerificationError,
    compare_project_observations,
    receipt_path_from_pr_body,
    run_gate,
)


def good_verify():
    return {
        "ok": True,
        "digest": "d" * 64,
        "manifest_digest_checked": True,
        "errors": [],
    }


def observed(code=0, command="python -m pytest -q"):
    return GateObservation(
        index=0,
        argv=tuple(command.split(" ")),
        exit_code=code,
        log_sha256="b" * 64,
        elapsed_seconds=0.1,
    )


def attested(code=0, command="python -m pytest -q"):
    return [{"command": command, "exit_code": code, "log_sha256": "a" * 64}]


def test_receipt_reference_is_exactly_one_repo_relative_trailer():
    body = "Summary\n\nbernstein-receipt-bundle: .bernstein/receipts/result.json\n"
    assert receipt_path_from_pr_body(body) == ".bernstein/receipts/result.json"
    for bad in (
        "no trailer",
        "bernstein-receipt-bundle: /tmp/x.json",
        "bernstein-receipt-bundle: ../x.json",
        "bernstein-receipt-bundle: C:\\tmp\\x.json",
        "bernstein-receipt-bundle: a.json\nbernstein-receipt-bundle: b.json",
    ):
        with pytest.raises(ProjectVerificationError):
            receipt_path_from_pr_body(bad)


def test_honest_independent_rerun_is_green_even_when_logs_differ():
    result = compare_project_observations(
        head_sha="1" * 40,
        manifest_digest="2" * 64,
        bundle_verification=good_verify(),
        attested_gates=attested(),
        observed_gates=[observed()],
    )
    assert result.ok
    assert result.gates[0]["log_digest_equal"] is False


def test_tampered_bundle_keeps_field_level_error():
    verify = good_verify()
    verify.update({"ok": False, "errors": [{"field": "patch", "message": "digest mismatch"}]})
    result = compare_project_observations(
        head_sha="1" * 40,
        manifest_digest="2" * 64,
        bundle_verification=verify,
        attested_gates=attested(),
        observed_gates=[observed()],
    )
    assert not result.ok
    assert result.errors[0].field == "bundle.patch"


def test_unchecked_manifest_is_never_reported_verified():
    verify = good_verify()
    verify["manifest_digest_checked"] = False
    result = compare_project_observations(
        head_sha="1" * 40,
        manifest_digest="2" * 64,
        bundle_verification=verify,
        attested_gates=attested(),
        observed_gates=[observed()],
    )
    assert not result.ok
    assert any(e.field == "bundle.manifest_sha256" for e in result.errors)


def test_named_gate_divergence_is_red():
    result = compare_project_observations(
        head_sha="1" * 40,
        manifest_digest="2" * 64,
        bundle_verification=good_verify(),
        attested_gates=attested(0),
        observed_gates=[observed(1)],
    )
    assert not result.ok
    fields = {error.field for error in result.errors}
    assert "gates[0].exit_code" in fields
    assert "gates[0].project_exit_code" in fields


def test_gate_count_or_command_drift_is_field_level():
    result = compare_project_observations(
        head_sha="1" * 40,
        manifest_digest="2" * 64,
        bundle_verification=good_verify(),
        attested_gates=attested(command="python tests.py"),
        observed_gates=[observed(command="python other.py")],
    )
    assert not result.ok
    assert any(error.field == "gates[0].command" for error in result.errors)


def test_gate_launcher_uses_argv_not_shell(tmp_path: Path):
    script = tmp_path / "gate.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    result = run_gate(
        ["python", str(script)], cwd=tmp_path, index=0, timeout_seconds=5
    )
    assert result.exit_code == 0
    assert not result.killed
    assert len(result.log_sha256) == 64


def test_gate_environment_strips_secret_shaped_extra(tmp_path: Path):
    script = tmp_path / "env.py"
    script.write_text(
        "import os,sys; sys.exit(1 if os.getenv('MY_SECRET') else 0)\n",
        encoding="utf-8",
    )
    result = run_gate(
        ["python", str(script)],
        cwd=tmp_path,
        index=0,
        timeout_seconds=5,
        env={"MY_SECRET": "canary"},
    )
    assert result.exit_code == 0
