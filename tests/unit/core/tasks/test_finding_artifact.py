import pytest

from bernstein.core.evidence.run_artifacts import ArtifactPayload
from bernstein.core.tasks.artifacts import ArtifactKind, CanonicalisationError, artifact_content_hash


def _finding_envelope(start_line: int, snippet: str) -> dict[str, object]:
    return {
        "sarif_result": {
            "ruleId": "G101",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": start_line, "snippet": {"text": snippet}},
                    }
                }
            ],
        },
        "provenance": {
            "tool": "gitleaks",
            "tool_version": "8.18.0",
            "pinned_ruleset_or_feed_digest": "sha256:abc",
            "invocation_argv_hash": "sha256:def",
            "target": "src/app.py",
        },
    }


def test_finding_identity_stable_across_line_shift():
    hash_10 = artifact_content_hash(ArtifactKind.FINDING, _finding_envelope(10, "password = 'hunter2'"))
    hash_11 = artifact_content_hash(ArtifactKind.FINDING, _finding_envelope(11, "password = 'hunter2'"))
    assert hash_10 == hash_11


def test_finding_identity_changes_when_snippet_changes():
    hash_1 = artifact_content_hash(ArtifactKind.FINDING, _finding_envelope(10, "password = 'hunter2'"))
    hash_2 = artifact_content_hash(ArtifactKind.FINDING, _finding_envelope(10, "password = 'hunter3'"))
    assert hash_1 != hash_2


def test_finding_address_matches_the_evidence_writer():
    envelope = _finding_envelope(10, "password = 'hunter2'")
    address = artifact_content_hash(ArtifactKind.FINDING, envelope)
    payload = ArtifactPayload.finding(envelope["sarif_result"], **envelope["provenance"])
    assert address == payload.to_content_dict()["address"]


def test_finding_rejects_an_empty_mapping():
    with pytest.raises(CanonicalisationError):
        artifact_content_hash(ArtifactKind.FINDING, {})
