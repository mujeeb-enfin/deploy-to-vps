/**
 * scripts/ci/security/verdict.mjs — the tiered gating decision, in ONE place.
 *
 * Every scanner job is configured to exit 0. Nothing fails a pull request
 * except this function. That is deliberate: spreading `exit-code:` flags across
 * six scanner jobs makes "why did my PR go red?" unanswerable, and it needs six
 * required status checks on the branch instead of one.
 *
 * THE TIERS, chosen for what this repository actually is — a PUBLIC composite
 * GitHub Action with no application code and no dependency manifest:
 *
 *   BLOCKING
 *     - any gitleaks hit introduced by this pull request
 *     - an unpinned third-party `uses:` (CONTRIBUTING.md mandates SHA pinning,
 *       and supply-chain pinning is the single most consequential control in a
 *       security-focused action that other people run in their own CI)
 *     - actionlint problems introduced by this pull request — a broken workflow
 *       reaches consumers as a failed deploy, not as a style nit
 *     - Trivy CRITICAL/HIGH misconfigurations introduced by this pull request
 *     - repo-rule violations introduced by this pull request
 *
 *   ADVISORY (reported, never blocks)
 *     - OWASP Dependency-Check: this repository has no dependency manifest, so
 *       it has nothing to analyse; kept for coverage reporting only
 *     - ZAP: only runs when SCAN_TARGET_URL is configured, and scans a site
 *       that is not built from this repository
 *     - SonarQube: quality signal, not a security gate
 *     - anything with no published fix, MEDIUM/LOW severity, or on a line this
 *       pull request did not touch
 *
 * WHY PRE-EXISTING FINDINGS DO NOT BLOCK: failing every pull request for debt
 * it did not create makes the gate useless and it gets switched off. The debt
 * stays visible in the report instead.
 */

/** Rule ids that block regardless of who introduced them. */
const ALWAYS_BLOCKING_RULE_IDS = new Set([
  // An unpinned action is exploitable by whoever controls the upstream tag,
  // independently of which commit added it. Reviewing it "later" is not a
  // control — it is exposure that persists until the pin lands.
  "repo-rules/unpinned-action-reference",
]);

/**
 * @param {import('./types.mjs').AttributedSecurityFinding} finding
 * @returns {boolean}
 */
function isBlockingFinding(finding) {
  if (ALWAYS_BLOCKING_RULE_IDS.has(finding.ruleId)) return true;

  switch (finding.tool) {
    case "gitleaks":
      // A pre-existing leak is a rotation task, not a merge blocker — and it is
      // only actionable by whoever committed it.
      return finding.wasIntroducedByThisPullRequest;

    case "actionlint":
    case "repo-rules":
      return finding.wasIntroducedByThisPullRequest;

    case "trivy":
      return (
        finding.wasIntroducedByThisPullRequest &&
        (finding.severity === "CRITICAL" || finding.severity === "HIGH")
      );

    case "owasp-dependency-check":
    case "zap":
    case "sonarqube":
    case "waf-lint":
      return false;

    default:
      return false;
  }
}

/**
 * Stamp the final `isBlocking` decision on every finding.
 * @param {import('./types.mjs').AttributedSecurityFinding[]} findings
 * @returns {import('./types.mjs').AttributedSecurityFinding[]}
 */
export function decideBlockingFindings(findings) {
  return findings.map((finding) => ({ ...finding, isBlocking: isBlockingFinding(finding) }));
}

/**
 * @param {import('./types.mjs').AttributedSecurityFinding[]} findings
 * @returns {number}
 */
export function countBlockingFindings(findings) {
  return findings.filter((finding) => finding.isBlocking).length;
}
