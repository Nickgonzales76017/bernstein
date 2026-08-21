"""Project-side verification for volunteer result receipts (#3880).

This module is intentionally independent from the donor-side gate runner. A
maintainer's CI must form a second opinion from the project's committed
volunteer manifest; sharing donor execution code would collapse the two
observations into one implementation.

The public helpers are pure except ``run_gate``. Workflows can therefore split
untrusted execution from trusted comparison/reporting without passing code or
shell fragments across the privilege boundary.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

PROJECT_VERIFICATION_SCHEMA = "bernstein.project-verification.v1"
RECEIPT_TRAILER = "bernstein-receipt-bundle"
MAX_RECEIPT_PATH_CHARS = 512
MAX_GATE_OUTPUT_BYTES = 4 * 1024 * 1024

_TRAILER_RE = re.compile(
    rf"(?mi)^\s*{re.escape(RECEIPT_TRAILER)}\s*:\s*(\S+)\s*$"
)
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


class ProjectVerificationError(ValueError):
    """Malformed project-verification input, before a verdict exists."""


@dataclass(frozen=True, slots=True)
class FieldError:
    field: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"field": self.field, "message": self.message}


@dataclass(frozen=True, slots=True)
class GateObservation:
    """One project-side gate execution, as bounded data only."""

    index: int
    argv: tuple[str, ...]
    exit_code: int
    log_sha256: str
    elapsed_seconds: float
    killed: bool = False
    output_truncated: bool = False

    @property
    def command(self) -> str:
        # Receipt v1 stores a display string rather than argv. Match the
        # donor-side producer's historical spelling for comparison; policy
        # identity itself is bound by the manifest digest and project CI runs
        # the manifest argv directly.
        return " ".join(self.argv)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "argv": list(self.argv),
            "command": self.command,
            "exit_code": self.exit_code,
            "log_sha256": self.log_sha256,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "killed": self.killed,
            "output_truncated": self.output_truncated,
        }


@dataclass(frozen=True, slots=True)
class ProjectVerification:
    ok: bool
    head_sha: str
    bundle_digest: str
    manifest_digest: str
    bundle_verified: bool
    manifest_digest_checked: bool
    gates: tuple[dict[str, Any], ...]
    errors: tuple[FieldError, ...]
    schema: str = PROJECT_VERIFICATION_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "ok": self.ok,
            "head_sha": self.head_sha,
            "bundle_digest": self.bundle_digest,
            "manifest_digest": self.manifest_digest,
            "bundle_verified": self.bundle_verified,
            "manifest_digest_checked": self.manifest_digest_checked,
            "gates": [dict(gate) for gate in self.gates],
            "errors": [error.to_dict() for error in self.errors],
        }


def _repo_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RECEIPT_PATH_CHARS:
        raise ProjectVerificationError("receipt bundle path is empty or too long")
    if "\x00" in value or value.startswith(("/", "\\")) or _WINDOWS_DRIVE_RE.match(value):
        raise ProjectVerificationError("receipt bundle path must be repository-relative")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ProjectVerificationError("receipt bundle path must not contain traversal components")
    return path.as_posix()


def receipt_path_from_pr_body(body: str) -> str:
    """Extract one bounded, repository-relative receipt trailer from a PR body."""
    if not isinstance(body, str):
        raise ProjectVerificationError("pull request body must be text")
    matches = _TRAILER_RE.findall(body)
    if len(matches) != 1:
        raise ProjectVerificationError(
            f"pull request must contain exactly one {RECEIPT_TRAILER}: trailer"
        )
    return _repo_relative_path(matches[0])


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _bounded_gate_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """A no-secret baseline for executing fork-controlled project gates."""
    keep = ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    if extra:
        for key, value in extra.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ProjectVerificationError("gate environment must contain strings")
            env[key] = value
    for key in tuple(env):
        upper = key.upper()
        if "TOKEN" in upper or "SECRET" in upper or "PASSWORD" in upper or upper.endswith("_KEY"):
            env.pop(key, None)
    return env


def _read_bounded(handle: Any) -> tuple[bytes, bool]:
    handle.seek(0)
    data = handle.read(MAX_GATE_OUTPUT_BYTES + 1)
    return data[:MAX_GATE_OUTPUT_BYTES], len(data) > MAX_GATE_OUTPUT_BYTES


def run_gate(
    argv: Sequence[str],
    *,
    cwd: Path,
    index: int,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
) -> GateObservation:
    """Execute one manifest argv without a shell and return bounded evidence.

    The process gets its own process group. On timeout the whole group is
    terminated before the observation is materialized, preventing a gate from
    leaving a background writer racing the result artifact.
    """
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ProjectVerificationError("gate argv must contain non-empty strings")
    if timeout_seconds <= 0:
        raise ProjectVerificationError("gate timeout must be positive")

    start = time.monotonic()
    killed = False
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=_bounded_gate_env(env),
                stdout=stdout,
                stderr=stderr,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            elapsed = time.monotonic() - start
            return GateObservation(
                index=index,
                argv=tuple(argv),
                exit_code=127,
                log_sha256=sha256_text(f"spawn-error:{type(exc).__name__}"),
                elapsed_seconds=elapsed,
            )

        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            killed = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            exit_code = 124

        out, out_truncated = _read_bounded(stdout)
        err, err_truncated = _read_bounded(stderr)

    log = out.decode("utf-8", errors="replace") + err.decode("utf-8", errors="replace")
    return GateObservation(
        index=index,
        argv=tuple(argv),
        exit_code=int(exit_code),
        log_sha256=sha256_text(log),
        elapsed_seconds=time.monotonic() - start,
        killed=killed,
        output_truncated=out_truncated or err_truncated,
    )


def compare_project_observations(
    *,
    head_sha: str,
    manifest_digest: str,
    bundle_verification: Mapping[str, Any],
    attested_gates: Sequence[Mapping[str, Any]],
    observed_gates: Sequence[GateObservation | Mapping[str, Any]],
) -> ProjectVerification:
    """Compare the signed donor claim with an independent project-side run."""
    errors: list[FieldError] = []

    bundle_ok = bundle_verification.get("ok") is True
    manifest_checked = bundle_verification.get("manifest_digest_checked") is True
    bundle_digest = bundle_verification.get("digest")
    if not isinstance(bundle_digest, str):
        bundle_digest = ""
    if not bundle_ok:
        for item in bundle_verification.get("errors", []):
            if isinstance(item, Mapping):
                errors.append(
                    FieldError(
                        field=f"bundle.{item.get('field', '<unknown>')}",
                        message=str(item.get("message", "verification failed")),
                    )
                )
        if not errors:
            errors.append(FieldError("bundle", "offline receipt verification failed"))
    if not manifest_checked:
        errors.append(
            FieldError(
                "bundle.manifest_sha256",
                "receipt was not checked against the project's manifest digest",
            )
        )

    observed: list[dict[str, Any]] = []
    for gate in observed_gates:
        observed.append(gate.to_dict() if isinstance(gate, GateObservation) else dict(gate))

    if len(attested_gates) != len(observed):
        errors.append(
            FieldError(
                "gates",
                f"bundle attests {len(attested_gates)} gate(s), project CI observed {len(observed)}",
            )
        )

    table: list[dict[str, Any]] = []
    width = max(len(attested_gates), len(observed))
    for index in range(width):
        attested = dict(attested_gates[index]) if index < len(attested_gates) else {}
        actual = observed[index] if index < len(observed) else {}
        expected_command = attested.get("command")
        actual_command = actual.get("command")
        expected_exit = attested.get("exit_code")
        actual_exit = actual.get("exit_code")

        if index >= len(attested_gates):
            errors.append(FieldError(f"gates[{index}]", "project CI observed an un-attested gate"))
        elif index >= len(observed):
            errors.append(FieldError(f"gates[{index}]", "attested gate was not observed by project CI"))
        else:
            if expected_command != actual_command:
                errors.append(
                    FieldError(
                        f"gates[{index}].command",
                        "attested command differs from project manifest gate",
                    )
                )
            if expected_exit != actual_exit:
                errors.append(
                    FieldError(
                        f"gates[{index}].exit_code",
                        f"bundle attests {expected_exit!r}, project CI observed {actual_exit!r}",
                    )
                )
            if actual_exit != 0:
                errors.append(FieldError(f"gates[{index}].project_exit_code", f"project gate exited {actual_exit!r}"))

        table.append(
            {
                "index": index,
                "command": actual_command or expected_command or "",
                "attested_exit_code": expected_exit,
                "observed_exit_code": actual_exit,
                "attested_log_sha256": attested.get("log_sha256"),
                "observed_log_sha256": actual.get("log_sha256"),
                "log_digest_equal": (
                    isinstance(attested.get("log_sha256"), str)
                    and attested.get("log_sha256") == actual.get("log_sha256")
                ),
            }
        )

    return ProjectVerification(
        ok=not errors,
        head_sha=head_sha,
        bundle_digest=bundle_digest,
        manifest_digest=manifest_digest,
        bundle_verified=bundle_ok,
        manifest_digest_checked=manifest_checked,
        gates=tuple(table),
        errors=tuple(errors),
    )


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
