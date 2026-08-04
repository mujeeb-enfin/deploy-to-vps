# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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