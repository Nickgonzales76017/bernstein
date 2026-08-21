from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VERIFY = ROOT / ".github" / "workflows" / "volunteer-receipt-verify.yml"
REPORT = ROOT / ".github" / "workflows" / "volunteer-receipt-report.yml"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_fork_execution_and_check_write_are_separate_workflows() -> None:
    verify = _text(VERIFY)
    report = _text(REPORT)

    assert "pull_request_target" not in verify
    assert "workflow_run:" not in verify
    assert "pull_request:" in verify
    assert "checks: write" not in verify
    assert "contents: read" in verify

    assert "workflow_run:" in report
    assert 'workflows: ["Volunteer receipt verification"]' in report
    assert "# zizmor: ignore[dangerous-triggers]" in report
    assert "checks: write" in report
    assert "actions: read" in report
    assert "contents: read" in report
    assert "pull-requests: read" in report
    assert "actions/checkout@" not in report


def test_privileged_report_never_executes_repository_code() -> None:
    report = _text(REPORT)

    forbidden = (
        "uv run",
        "pytest",
        "pip install",
        "poetry install",
        "./candidate",
        "working-directory:",
    )
    for needle in forbidden:
        assert needle not in report


def test_candidate_checkout_cannot_persist_credentials() -> None:
    verify = _text(VERIFY)
    candidate = verify.split("- name: Checkout candidate head", 1)[1].split(
        "- name: Set up Python", 1
    )[0]

    assert "persist-credentials: false" in candidate
    assert "github.event.pull_request.head.sha" in candidate
    assert "github.event.pull_request.head.repo.full_name" in candidate


def test_privileged_report_authenticates_the_producer_definition() -> None:
    report = _text(REPORT)

    assert "EXPECTED_PRODUCER_PATH: .github/workflows/volunteer-receipt-verify.yml" in report
    assert 'run.get("path") != expected_path' in report
    assert 'run.get("head_sha") != expected_head' in report
    assert 'current_head != expected_head' in report
    assert 'candidate_blob != trusted_blob' in report
    assert 'reason = "producer_workflow_changed"' in report or 'TrustError("producer_workflow_changed")' in report
    assert "Build untrusted-producer failure check" in report
    assert "Its artifact was not downloaded or interpreted" in report


def test_artifact_is_unreachable_until_producer_is_trusted() -> None:
    report = _text(REPORT)

    find_artifact = report.split("- name: Find verdict artifact", 1)[1].split(
        "- name: Build missing-artifact failure check", 1
    )[0]
    download = report.split("- name: Download verdict artifact", 1)[1].split(
        "- name: Validate and render check payload", 1
    )[0]

    assert "steps.producer.outputs.trusted == 'true'" in find_artifact
    assert "steps.producer.outputs.trusted == 'true'" in download


def test_no_trailer_does_not_create_a_noisy_failure_check() -> None:
    report = _text(REPORT)

    assert 'requested = "bernstein-receipt-bundle:" in body' in report
    assert 'reason = "not_requested"' in report
    publish = report.split("- name: Publish advisory Check Run", 1)[1]
    assert "steps.producer.outputs.requested == 'true'" in publish


def test_verdict_is_the_only_cross_privilege_artifact() -> None:
    verify = _text(VERIFY)
    report = _text(REPORT)

    artifact_name = "volunteer-project-verification"
    assert f"name: {artifact_name}" in verify
    assert f'== "{artifact_name}"' in report
    assert "volunteer-project-verification.json" in verify
    assert "volunteer-project-verification.json" in report


def test_actions_are_commit_pinned() -> None:
    for path in (VERIFY, REPORT):
        for line in _text(path).splitlines():
            stripped = line.strip()
            if not stripped.startswith("uses:"):
                continue
            reference = stripped.split("uses:", 1)[1].strip().split()[0]
            if reference.startswith("./"):
                continue
            assert "@" in reference
            sha = reference.rsplit("@", 1)[1]
            assert len(sha) == 40
            assert all(ch in "0123456789abcdef" for ch in sha)


def test_untrusted_exception_text_is_not_exported() -> None:
    verify = _text(VERIFY)

    assert 'f"{type(exc).__name__}: {exc}"' not in verify
    assert "project verification could not complete" in verify


def test_missing_artifact_produces_a_failure_check() -> None:
    report = _text(REPORT)

    assert "Build missing-artifact failure check" in report
    assert '"conclusion": "failure"' in report
    assert "No verification claim is made." in report


def test_malformed_artifact_also_produces_a_failure_check() -> None:
    report = _text(REPORT)

    assert "continue-on-error: true" in report
    assert "Build malformed-artifact failure check" in report
    assert "steps.render.outcome == 'failure'" in report
    assert "verdict was malformed" in report
    assert "untrusted artifact is not echoed here" in report


def test_privileged_renderer_bounds_untrusted_markdown() -> None:
    report = _text(REPORT)

    assert "MAX_ERRORS = 128" in report
    assert "MAX_GATES = 128" in report
    assert "MAX_TEXT = 4096" in report
    assert 're.sub(r"[\\x00-\\x1f\\x7f-\\x9f]", " ", text)' in report
    assert '.replace("|", "\\\\|")' in report
    assert '.replace("`", "\'")' in report
