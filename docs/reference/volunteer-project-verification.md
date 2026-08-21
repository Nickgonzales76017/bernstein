# Volunteer project-side receipt verification

A donor-side receipt proves that a worker signed a particular patch and a set
of gate observations. It does **not** prove that the project independently saw
the same gate outcome. Project-side verification is the second observation.

This surface is advisory. Maintainers, branch protection, and ordinary review
remain the authority for merging a contribution.

## Receipt reference in a volunteer pull request

A volunteer PR that wants project-side verification carries exactly one
repository-relative trailer:

```text
bernstein-receipt-bundle: .bernstein/receipts/result.json
```

The named file is resolved inside the pull-request head. Absolute POSIX paths,
Windows drive paths, traversal components, empty paths, and duplicate trailers
are malformed input. This line is a reference, not an instruction: its contents
never become a shell command.

The bundle remains independently verifiable with the existing command:

```bash
bernstein receipt verify .bernstein/receipts/result.json \
  --expected-manifest-digest <project-manifest-digest> \
  --json
```

The expected manifest digest is derived from the **base project's** committed
`.bernstein/volunteer.json`, not from the PR head. A worker-supplied manifest
hash is evidence carried by the worker; it becomes a project-policy claim only
when compared with the project's manifest.

## Two observations, not one shared runner

The project verifier deliberately does not call the donor-side gate runner.
Both read the same versioned volunteer-manifest contract, but the project path
executes the manifest argv independently. Sharing one execution helper would
make implementation bugs correlated and weaken the point of the second
observation.

The comparison table treats these fields differently:

| Field | Verdict role |
|---|---|
| DSSE / bundle verification | hard requirement |
| expected manifest digest checked | hard requirement |
| gate count and command | hard requirement |
| donor exit code vs project exit code | hard requirement |
| project exit code | must be zero |
| gate log digest equality | evidence only |

Log bytes are intentionally not a hard equality check. Two honest executions
can differ in elapsed times, temporary paths, ordering noise, or other
non-semantic output while producing the same gate verdict. Both log digests are
retained so a reviewer can inspect the difference without turning nondeterminism
into a false failure.

## GitHub Actions privilege boundary

Project verification is split across two workflows.

### 1. `Volunteer receipt verification`

Triggered by ordinary `pull_request`.

- token: `contents: read` only;
- no project secrets;
- checks out the trusted base and candidate fork separately;
- loads Bernstein and the volunteer manifest from the trusted base;
- verifies the candidate receipt against the trusted manifest digest;
- executes manifest gates against the candidate checkout;
- runs each gate as argv, never through a shell;
- gives gate children a stripped environment;
- bounds captured output and terminates the process group on timeout;
- writes one bounded JSON verdict artifact.

This is the workflow allowed to execute fork-controlled code. It never has
`checks: write`.

### 2. `Volunteer receipt report`

Triggered by `workflow_run` after the first workflow completes.

- token: `actions: read`, `contents: read`, `checks: write`;
- never checks out repository code;
- never executes code or command text from the pull request;
- downloads only the named verdict artifact from that exact workflow run;
- validates schema, bounded collection sizes, and `head_sha` against the
  trusted `workflow_run` metadata;
- renders bounded data into an advisory Check Run.

A missing verdict artifact is a failing check with **no verification claim**.
The privileged workflow must not silently interpret an absent artifact as a
skip or success.

## Why not `pull_request_target`?

`pull_request_target` can receive base-repository privileges while processing a
fork PR. Combining it with a checkout or execution of the fork head creates the
classic privileged-untrusted-code boundary failure. The two-workflow design is
more verbose because it preserves the actual trust boundary: fork code may run,
or a workflow may write a Check Run, but no execution context gets both powers.

Do not collapse the two workflows for convenience.

## Failure semantics

A failed check names the field that diverged where possible, for example:

```text
bundle.patch: digest mismatch
gates[1].exit_code: bundle attests 0, project CI observed 1
gates[1].project_exit_code: project gate exited 1
```

Malformed outer input is intentionally less descriptive when the underlying
exception could contain attacker-controlled bytes. The untrusted workflow
records a fixed failure category instead of forwarding raw exception text into
a maintainer-facing privileged Check Run.

## Source

- `src/bernstein/core/volunteer/project_verification.py`
- `.github/workflows/volunteer-receipt-verify.yml`
- `.github/workflows/volunteer-receipt-report.yml`
- `tests/unit/volunteer/test_project_verification.py`
- `tests/unit/volunteer/test_project_verification_workflows.py`
