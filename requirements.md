# Developer Requirements

A consolidated checklist for developers setting up the **`Deploy to VPS`** action and its CI / security-scanning pipeline. Read this top-to-bottom on a fresh repo, or jump to the section you need.

> If you are a **downstream consumer** (you want to call `mujeeb-enfin/deploy-to-vps@v1` from your own repo), you only need sections 1, 2, and 4.
>
> If you are a **maintainer** of this repo, you additionally need sections 3, 5, and 6.

---

## 1. Account & Repository

- A GitHub account with permission to enable GitHub Actions on the target repository.
- **Settings → Actions → General → Allow all actions** (or "Allow [owner]/[repo] actions and any third-party actions" if you have an allow-list).
- **Settings → Code security → Dependabot → Enabled** (recommended).
- A repository with a default branch called `main` (the workflows assume this).

## 2. Required Secrets

Set these under **Repo → Settings → Secrets and variables → Actions**. Without them the deploy workflows cannot run.

| Secret | Required for | Description |
|---|---|---|
| `VPS_HOST` | Deploy | IP or hostname of the target VPS. |
| `VPS_USERNAME` | Deploy | SSH user on the VPS (recommend a non-root deploy user). |
| `VPS_SSH_KEY` | Deploy | Private SSH key (PEM, including `BEGIN`/`END` lines). Authorize the matching public key in the user's `~/.ssh/authorized_keys`. |
| `VPS_PASSWORD` | Optional | Only if you switch the workflow from `key:` to `password:`. Most setups use keys. |
| `VPS_FINGERPRINT` | Optional | SHA256 fingerprint of the VPS host key. Strongly recommended for production. Get it with: `ssh-keyscan -t ed25519 <VPS_HOST> \| ssh-keygen -lf -`. |
| `GITHUB_TOKEN` | Auto | Provided automatically by GitHub. Used by gitleaks. |

### Optional scanner secrets

| Secret / Variable | Used by | Purpose |
|---|---|---|
| `SONAR_TOKEN` | `sonarqube.yml` | SonarCloud or self-hosted SonarQube token. Job is skipped if absent. |
| `SONAR_HOST_URL` | `sonarqube.yml` | SonarQube server URL (defaults to SonarCloud). |
| `SCAN_TARGET_URL` | `zap.yml` | Live URL for the passive baseline scan. Job is skipped if absent. Use `vars.SCAN_TARGET_URL` (repo variable) for non-secret URLs. |

## 3. Local Tooling (maintainers only)

To run the same CI checks locally before pushing:

| Tool | Purpose | Install |
|---|---|---|
| Node.js ≥ 20 | Runs `actionlint` and `yamllint` via `npx`. | https://nodejs.org |
| `actionlint` | Validates workflow YAML and catches common issues. | `npx actionlint` |
| `yamllint` | Enforces YAML style. | `npx yamllint .` |
| `shellcheck` | Lints the embedded shell script in `action.yml`. | `brew install shellcheck` / `apt install shellcheck` |
| `docker` | Required by `test.yml` to run `shellcheck` against the embedded script via `koalaman/shellcheck:stable`. | https://docker.com |
| `git` | Tagging releases. | Already installed on most dev machines. |
| `gh` (optional) | Set secrets and create releases from the CLI. | https://cli.github.com |

### One-shot local check

```bash
npx actionlint
npx yamllint .
docker run --rm -v "$PWD:/src" -w /src koalaman/shellcheck:stable \
  <(awk '/^          script: \|/{f=1;next} f && /^          [a-zA-Z]/{f=0} f{sub(/^          /,"");print}' action.yml)

# Security checks — no install step; Node standard library only.
node scripts/ci/repo-rules.mjs --out=reports/repo-rules.json --exit-code
node scripts/ci/waf/waf-lint.mjs --out=reports/waf-lint.json
node scripts/ci/security-report.mjs --repo-rules=reports/repo-rules.json
node --test scripts/ci/__tests__/security.test.mjs
```

The `awk` one-liner extracts the embedded `script:` block from `action.yml` so shellcheck can lint it.

The `scripts/ci/**` tools have **no dependencies** — they are plain Node ES
modules using only the standard library, so there is no `package.json` and
nothing to install. Outside a pull request the reporter prints findings without
attribution and does not set an exit code, because there is no diff to scope
against.

## 4. VPS Prerequisites

Install only what your chosen `strategy` requires. The action assumes the SSH user can `cd` into `project_path` and that the directory is a git checkout of the source repo.

| Strategy | Required on the VPS |
|---|---|
| `node-pm2` | `nvm` (https://github.com/nvm-sh/nvm) + the Node.js version you set in `node_version` (default `22`). `npm install -g pm2`. |
| `node-docker` | `nvm` + Node.js, **plus** Docker + Compose **V2** (the `docker compose` plugin — not the legacy `docker-compose`). |
| `static` | `nginx` (or whatever you set in `reload_service`), `sudo` rights for the SSH user (scoped to the exact commands below), and `rsync`. |
| `custom` | Whatever your `custom_script` invokes. The action does not assume anything. |

### Sudoers snippet for the `static` strategy

Restrict the deploy user to **only** the commands the action needs:

```bash
sudo visudo -f /etc/sudoers.d/deploy
```

```
your-vps-user ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx
your-vps-user ALL=(ALL) NOPASSWD: /usr/bin/rsync
your-vps-user ALL=(ALL) NOPASSWD: /usr/bin/mkdir
```

Do **not** give the deploy user blanket `NOPASSWD: ALL`.

## 5. CI / Security Scans — what runs when

| Workflow | Trigger | Cadence | Fail threshold | Notes |
|---|---|---|---|---|
| `pr-security.yml` | PR | every PR | see below | **The security gate.** Scanners never fail; one reporter blames, comments and decides. Require `security-report` in branch protection. |
| `test.yml` | push, PR | every push | exit non-zero | actionlint + yamllint + shellcheck. |
| `gitleaks.yml` | push, schedule | push to `main` + nightly 03:00 UTC | any secret found | Deep history scan. PR coverage comes from `pr-security.yml`. |
| `owasp.yml` | push, PR, schedule | every push + weekly Mon 04:00 UTC | CVSS ≥ 7.0 | Uploads SARIF to Code Scanning. **Advisory only — see the note below.** |
| `trivy.yml` | push, schedule | push to `main` + weekly Mon 05:00 UTC | CRITICAL or HIGH | Filesystem vulns, IaC misconfigs, secret leaks. PR coverage comes from `pr-security.yml`. |
| `sonarqube.yml` | push, PR | every push | SonarQube quality gate | Skipped if `SONAR_TOKEN` is not set. |
| `zap.yml` | push, PR, schedule | every push + weekly Mon 06:00 UTC | ZAP `WARN` or worse | Skipped if `SCAN_TARGET_URL` is not set. |

**Why `gitleaks.yml` and `trivy.yml` no longer run on pull requests:** they used
to fail PRs independently, contradicting the unified gate and producing two
different answers to "is this PR safe?". Pull-request coverage is unchanged — it
is delivered through `pr-security.yml`'s single attributed check instead.

**What blocks a merge** (`scripts/ci/security/verdict.mjs` is the single source
of truth):

| Finding | Blocks |
|---|---|
| Unpinned third-party `uses:` | **Always** — a mutable tag is exploitable until the pin lands |
| Secret introduced by this PR | Yes |
| CRITICAL/HIGH Trivy finding introduced by this PR | Yes |
| Shell template injection, missing `permissions:`, missing `set -euo pipefail` introduced by this PR | Yes |
| Anything pre-existing, or from OWASP / ZAP / SonarQube / waf-lint | No — advisory |

> **OWASP Dependency-Check finds nothing in this repository.** A composite action
> has no `package.json`, no lockfile and no dependency manifest, so there is
> nothing for it to analyse. It is retained for coverage reporting and is
> **advisory**; it must not be read as evidence that dependencies were verified.
> Third-party supply-chain risk here is controlled by SHA-pinning every `uses:`.

To disable a scanner you don't need, delete its workflow file. To change severity thresholds, edit the `severity:`, `failOnCVSS`, or `cmd_options:` lines inside the workflow. Full runbook: [`docs/SECURITY_CI.md`](docs/SECURITY_CI.md).

## 6. Public-Use / Versioning Model

This action is intended for **public use**. Consumers reference it as:

```yaml
- uses: mujeeb-enfin/deploy-to-vps@v1
```

- `@v1` is a floating major tag. You receive non-breaking updates automatically.
- `@v1.2.3` pins to a specific release for strict reproducibility.
- Breaking changes will bump the major tag to `@v2`. The `appleboy/ssh-action` SHA in `action.yml` will only change on a deliberate, reviewable commit.

### Cutting a release (maintainers)

```bash
# 1. Move the CHANGELOG entry from [Unreleased] into a new [x.y.z] section.
# 2. Tag the commit.
git tag -a v1.1.0 -m "v1.1.0"

# 3. STEP THAT IS EASY TO FORGET — move the floating major tag.
#    Pushing v1.1.0 does NOT move @v1. Consumers reference @v1, so skipping
#    this ships the release to nobody. In v1.0.0 the v1 tag was never pushed
#    at all, which made `uses: ...@v1` unresolvable for every consumer.
git tag -f -a v1 -m "Floating major tag for v1.x — currently v1.1.0"

# 4. Push both. The floating tag needs --force because it moves.
git push origin v1.1.0
git push --force origin v1

# 5. Verify BOTH resolve to the same commit before announcing.
git ls-remote --tags origin | grep -E 'v1\^|v1\.1\.0\^'

# 6. Create the GitHub Release from the tag.
gh release create v1.1.0 --title "v1.1.0 — <summary>" --notes-file <(sed -n '/## \[1.1.0\]/,/## \[1.0.0\]/p' CHANGELOG.md)
```

Moving `@v1` is deliberately manual so a bad release cannot auto-promote itself
to every consumer. Verify CI is green on the tagged commit **before** step 3 —
once `v1` moves, everyone using `@v1` picks it up on their next run.

## 7. Troubleshooting quick links

- "Permission denied (publickey)" → `README.md` §Troubleshooting row 1.
- "docker: command not found" → `README.md` §Troubleshooting row 2.
- "nvm: command not found" → `README.md` §Troubleshooting row 3.
- "git fetch failed: Permission denied (publickey)" → `README.md` §Troubleshooting row 4.
- "tag not found on checkout" → `README.md` §Troubleshooting row 5.

## 8. Things this action intentionally does **not** do

Keep this in mind before requesting features:

- **No OIDC / keyless SSH.** Long-lived SSH keys are required. For OIDC, run Teleport, step-ca, or Vault SSH externally and have them issue the cert that you pass in via `vps_ssh_key`.
- **No multi-server fan-out.** One deploy = one VPS. Run the action multiple times in a matrix for fan-out.
- **No health checks.** The action does not curl your service after deploy. Append your own health-check step.
- **No automatic rollbacks.** If a deploy fails, the previous container is already stopped (`docker compose down`). Capture a `before_deploy_commands` step that tags the previous release if you need rollback.
- **No SLSA provenance.** Composite actions cannot produce SLSA provenance natively.
