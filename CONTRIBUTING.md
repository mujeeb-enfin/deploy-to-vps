# Contributing

Thanks for your interest in improving this action! 🎉

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to its terms.

## How to Contribute

1. **Open an issue first** for non-trivial changes. Bug fixes for confirmed issues can skip this step.
2. **Fork the repository** and create a branch from `main`:
   - `feat/<short-description>` for new features
   - `fix/<short-description>` for bug fixes
   - `chore/<short-description>` for tooling, docs, refactors
3. **Make your changes.** Keep them focused — one logical change per PR.
4. **Run the linters and security checks locally** before pushing:
   ```bash
   npx actionlint
   npx yamllint .

   # Security checks — no install step; Node standard library only.
   node scripts/ci/repo-rules.mjs --out=reports/repo-rules.json --exit-code
   node scripts/ci/waf/waf-lint.mjs --out=reports/waf-lint.json
   node --test scripts/ci/__tests__/security.test.mjs
   ```
   The CI runs the same checks; PRs that fail them will not be merged.

   The "Coding Standards" rules below are **enforced, not merely documented** —
   `scripts/ci/repo-rules.mjs` checks SHA pinning, shell template injection,
   workflow `permissions:` blocks, `set -euo pipefail`, and input descriptions.
   See [`docs/SECURITY_CI.md`](docs/SECURITY_CI.md) for which of them block a
   merge and how to suppress a false positive without disabling a control.
5. **Update `CHANGELOG.md`** under the `## [Unreleased]` section.
6. **Update `README.md`** if you added, removed, or renamed any input or output.
7. **Open the PR** using the [PR template](.github/PULL_REQUEST_TEMPLATE.md). CI must be green before review.

## Coding Standards

### `action.yml`

- Every input must have a `description`. Be specific — it shows up in the GitHub Marketplace UI.
- Pin every `uses:` reference to a full 40-character commit SHA, **not** a tag.
- Pass all user-controlled values to the embedded script via `env:`, never by raw `${{ inputs.x }}` interpolation into `script: |`.
- Reference env vars in the script as `"$VAR_NAME"` with double quotes.

### Shell script (embedded in `action.yml`)

- Start with `set -euo pipefail`.
- Quote every variable expansion.
- Prefer `[ -f file ]` over `[[ -f file ]]` for POSIX portability.

### YAML

- 2-space indent, one blank line between top-level keys.
- Multi-line strings use `|` block scalar.
- No trailing whitespace.

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>
```

Common types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `ci`, `security`.

Examples:

```
feat(node-pm2): add skip_install input
fix(static): reload_service empty string now correctly skips reload
docs(readme): clarify vps_fingerprint usage
ci: pin actions/checkout to v4.2.2 SHA
```

## Reporting Security Issues

Please do **not** open a public issue for security problems. See [SECURITY.md](SECURITY.md).