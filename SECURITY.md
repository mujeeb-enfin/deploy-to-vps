# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| `v1.x`  | ✅ Active          |
| `< v1`  | ❌ End of life     |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security problems.**

Use one of the following private channels:

1. **GitHub private vulnerability reporting** (preferred): go to the **Security** tab of this repository and click **Report a vulnerability**.
2. **Email**: security@mr-innovations.com

### What to include

- A clear description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- The version tag (e.g. `v1.0.0`) and commit SHA affected.
- Any suggested fix, if you have one.

### Response timeline

| Stage                | Time-to-response |
|----------------------|------------------|
| Acknowledgement      | 3 business days  |
| Initial triage       | 7 business days  |
| Fix or mitigation    | 30 days for high-severity, 90 days for low/medium |
| Public disclosure    | Coordinated with the reporter once a fix ships |

## Automated controls

Since `v1.1.0` these are enforced in CI rather than left to code review. See
[`docs/SECURITY_CI.md`](docs/SECURITY_CI.md) for the full runbook.

| Control | Enforced by | Blocks a merge |
|---|---|---|
| Every third-party `uses:` pinned to a 40-character commit SHA | `scripts/ci/repo-rules.mjs` | **Always** |
| No `${{ inputs.* }}` / `${{ github.event.* }}` interpolated into a `run:` or `script:` block | `scripts/ci/repo-rules.mjs` | If introduced by the PR |
| Every workflow declares a least-privilege `permissions:` block | `scripts/ci/repo-rules.mjs` | If introduced by the PR |
| No secrets in the source or git history | gitleaks (full-history scan) | If introduced by the PR |
| No CRITICAL/HIGH filesystem or IaC findings | Trivy | If introduced by the PR |

Findings are attributed to the developer whose commit last touched the line and
reported through a single pull-request comment. Secret **values** are never
printed there — this is a public repository, so the comment is world-readable.

## Scope

In-scope:

- `action.yml` and the SSH session it orchestrates
- The example workflows under `.github/workflows/`
- Anything that could cause the action to execute attacker-controlled code on a consumer's VPS

Out-of-scope:

- Issues in `appleboy/ssh-action` — report upstream at <https://github.com/appleboy/ssh-action/issues>.
- Issues in third-party actions used by the example workflows.
- Social engineering or physical-access attacks.