/**
 * scripts/ci/security/types.mjs — the single normalized finding shape that every
 * scanner in this repository is translated into.
 *
 * WHY ZERO DEPENDENCIES: this repository is a composite GitHub Action with no
 * `package.json` and no build step. Adding TypeScript + a bundler + an npm
 * dependency tree to a SECURITY-focused action would enlarge the very supply
 * chain the action exists to keep small. These scripts are plain ES modules
 * that run on the Node.js already present on every GitHub runner — no install
 * step, no lockfile, no transitive dependencies. Types are expressed as JSDoc,
 * which editors understand without a compiler.
 *
 * WHY ONE SHAPE: the PR gate has to (a) blame each finding on the developer who
 * wrote the line, (b) render one grouped comment, and (c) produce a single
 * pass/fail verdict. Doing that against five different scanner outputs would
 * smear the tiering logic across five places. Normalizing first keeps the
 * blocking rule in one testable function (`decideBlockingFindings`).
 *
 * @typedef {'gitleaks'|'trivy'|'owasp-dependency-check'|'zap'|'sonarqube'|'repo-rules'|'actionlint'|'waf-lint'} SecurityToolName
 * @typedef {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'} FindingSeverity
 * @typedef {'exact'|'approximated'} FindingFidelity
 *
 * @typedef {object} SecurityFinding
 * @property {SecurityToolName} tool
 * @property {string}  ruleId          Vendor rule identifier.
 * @property {FindingSeverity} severity
 * @property {string}  title           One-line summary. MUST NOT contain a secret value.
 * @property {string}  detail          Explanation / remediation. MUST NOT contain a secret value.
 * @property {string|null} filePath    Repo-relative path, or null when not file-bound.
 * @property {number|null} startLine   1-indexed line within filePath.
 * @property {string|null} requestUrl  For DAST findings: the URL that triggered the rule.
 * @property {boolean} hasFixAvailable Dependency findings: is a fixed release published?
 * @property {string|null} fixedVersion
 * @property {FindingFidelity} fidelity
 * @property {string}  fingerprint     Stable identity across runs.
 *
 * @typedef {SecurityFinding & {
 *   blameCommitSha: string|null,
 *   blameAuthorName: string|null,
 *   blameGithubHandle: string|null,
 *   wasIntroducedByThisPullRequest: boolean,
 *   isBlocking: boolean,
 * }} AttributedSecurityFinding
 *
 * @typedef {object} PullRequestContext
 * @property {string} owner
 * @property {string} repo
 * @property {number} pullNumber
 * @property {string|null} pullAuthorHandle
 * @property {string} baseRef
 */

/**
 * Marker embedded in the pull-request comment so re-runs PATCH the existing
 * comment instead of appending a new one. A 12-commit pull request must not
 * grow 12 security comments.
 */
export const SECURITY_COMMENT_MARKER = "<!-- security-report:do-not-remove -->";

/** @type {Record<string, FindingSeverity>} */
const SARIF_LEVEL_TO_SEVERITY = {
  error: "HIGH",
  warning: "MEDIUM",
  note: "LOW",
  none: "INFO",
};

/**
 * Map a SARIF `level` to our severity vocabulary.
 * SARIF only has four levels, so this is a widening, not a precise mapping —
 * individual normalizers override it where the tool reports a real severity.
 * @param {string|undefined} sarifLevel
 * @returns {FindingSeverity}
 */
export function severityFromSarifLevel(sarifLevel) {
  return SARIF_LEVEL_TO_SEVERITY[String(sarifLevel ?? "").toLowerCase()] ?? "MEDIUM";
}

/**
 * Normalize a vendor severity string ("CRITICAL", "high", "Medium (High)"…).
 * @param {string|undefined} rawSeverity
 * @returns {FindingSeverity}
 */
export function normalizeSeverityWord(rawSeverity) {
  const leadingWord = String(rawSeverity ?? "").trim().split(/[\s(]/)[0].toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(leadingWord)) {
    return /** @type {FindingSeverity} */ (leadingWord);
  }
  return "INFO";
}

/**
 * Build a SecurityFinding with safe defaults, so each normalizer only states
 * what it actually knows.
 * @param {Partial<SecurityFinding> & Pick<SecurityFinding,'tool'|'ruleId'|'title'>} partialFinding
 * @returns {SecurityFinding}
 */
export function createFinding(partialFinding) {
  return {
    severity: "MEDIUM",
    detail: "",
    filePath: null,
    startLine: null,
    requestUrl: null,
    hasFixAvailable: false,
    fixedVersion: null,
    fidelity: "exact",
    fingerprint: [partialFinding.tool, partialFinding.ruleId, partialFinding.filePath ?? ""].join("|"),
    ...partialFinding,
  };
}

/**
 * Structured log line, matching the JSON-to-stdout convention used by the
 * workflows in this repository. Every entry carries level, component and event.
 * @param {'info'|'warn'|'error'} level
 * @param {string} component
 * @param {string} event
 * @param {Record<string, unknown>} payload
 */
export function emitLog(level, component, event, payload = {}) {
  process.stdout.write(JSON.stringify({ level, component, event, ...payload }) + "\n");
}
