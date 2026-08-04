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
2. **Email**: security@enfin.dev

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

## Scope

In-scope:

- `action.yml` and the SSH session it orchestrates
- The example workflows under `.github/workflows/`
- Anything that could cause the action to execute attacker-controlled code on a consumer's VPS

Out-of-scope:

- Issues in `appleboy/ssh-action` — report upstream at <https://github.com/appleboy/ssh-action/issues>.
- Issues in third-party actions used by the example workflows.
- Social engineering or physical-access attacks.