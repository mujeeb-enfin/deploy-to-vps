# Developer Requirements

A consolidated checklist for developers setting up the **`Deploy to VPS`** action and its CI / security-scanning pipeline. Read this top-to-bottom on a fresh repo, or jump to the section you need.

> If you are a **downstream consumer** (you want to call `mujeeb-enfin/git-actions@v1` from your own repo), you only need sections 1, 2, and 4.
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
```

The `awk` one-liner extracts the embedded `script:` block from `action.yml` so shellcheck can lint it.

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
| `test.yml` | push, PR | every push | exit non-zero | actionlint + yamllint + shellcheck. |
| `gitleaks.yml` | push, PR, schedule | every push + nightly 03:00 UTC | any secret found | Deep history scan on push to `main` and on the nightly schedule. |
| `owasp.yml` | push, PR, schedule | every push + weekly Mon 04:00 UTC | CVSS ≥ 7.0 | Uploads SARIF to the Code Scanning tab. |
| `trivy.yml` | push, PR, schedule | every push + weekly Mon 05:00 UTC | CRITICAL or HIGH severity | Scans filesystem: vulns, IaC misconfigs, secret leaks. |
| `sonarqube.yml` | push, PR | every push | SonarQube quality gate | Skipped if `SONAR_TOKEN` is not set. |
| `zap.yml` | push, PR, schedule | every push + weekly Mon 06:00 UTC | ZAP `WARN` or worse by default | Skipped if `SCAN_TARGET_URL` is not set. |

To disable a scanner you don't need, delete its workflow file. To change severity thresholds, edit the `severity:`, `failOnCVSS`, or `cmd_options:` lines inside the workflow.

## 6. Public-Use / Versioning Model

This action is intended for **public use**. Consumers reference it as:

```yaml
- uses: mujeeb-enfin/git-actions@v1
```

- `@v1` is a floating major tag. You receive non-breaking updates automatically.
- `@v1.2.3` pins to a specific release for strict reproducibility.
- Breaking changes will bump the major tag to `@v2`. The `appleboy/ssh-action` SHA in `action.yml` will only change on a deliberate, reviewable commit.

### Cutting a release (maintainers)

```bash
# 1. Bump the version in CHANGELOG.md (skip this if you've removed that file)
# 2. Tag the commit
git tag -s v1.0.0 -m "v1.0.0"
# 3. Push the tag
git push origin v1.0.0
# 4. Create the GitHub Release from the tag
gh release create v1.0.0 --generate-notes --title "v1.0.0"
```

Pushing a `v*` tag does **not** automatically move the floating `@v1` ref — that step is currently manual. If you want automation, add a `release.yml` workflow (not currently shipped; out of scope for the minimum viable setup).

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
