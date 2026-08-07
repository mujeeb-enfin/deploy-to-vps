/**
 * scripts/ci/security/normalize.mjs — translate scanner output into the shared
 * finding shape.
 *
 * SARIF FIRST, BY DESIGN. Every scanner already wired into this repository —
 * Trivy, OWASP Dependency-Check, ZAP, and gitleaks — emits SARIF, because each
 * one uploads to GitHub code scanning (free on public repositories). So the
 * primary normalizer here parses SARIF rather than five vendor-specific JSON
 * schemas. One parser, one set of tests, and any future SARIF-emitting scanner
 * is supported for free.
 *
 * SECRET SAFETY. gitleaks SARIF puts the matched text in
 * `locations[].physicalLocation.region.snippet.text`. That field is NEVER read.
 * The pull-request comment is visible to everyone with repository access and is
 * mirrored into notification emails, so echoing a leaked credential there would
 * widen the very leak the scanner just found. Only rule id, location and commit
 * are carried forward.
 */

import {
  createFinding,
  severityFromSarifLevel,
  normalizeSeverityWord,
} from "./types.mjs";

/**
 * Index a SARIF run's rule metadata by id, so a result can recover the severity
 * and help text that SARIF stores separately from the result itself.
 * @param {any} sarifRun
 */
function indexRulesById(sarifRun) {
  /** @type {Map<string, any>} */
  const rulesById = new Map();
  const driverRules = sarifRun?.tool?.driver?.rules ?? [];
  const extensionRules = (sarifRun?.tool?.extensions ?? []).flatMap((ext) => ext?.rules ?? []);
  for (const rule of [...driverRules, ...extensionRules]) {
    if (rule?.id) rulesById.set(rule.id, rule);
  }
  return rulesById;
}

/**
 * Pull the most specific severity SARIF offers: tools commonly stash the real
 * severity in `properties` (Trivy uses `security-severity`, a CVSS number)
 * rather than in the coarse four-value `level`.
 * @param {any} sarifResult
 * @param {any} sarifRule
 */
function resolveSeverity(sarifResult, sarifRule) {
  const vendorSeverity =
    sarifResult?.properties?.severity ??
    sarifRule?.properties?.severity ??
    sarifRule?.properties?.tags?.find?.((tag) => /^(critical|high|medium|low)$/i.test(tag));
  if (vendorSeverity) return normalizeSeverityWord(String(vendorSeverity));

  // CVSS "security-severity" is a 0.0-10.0 string. Map it onto our vocabulary
  // using the standard CVSS v3 bands so a 9.8 is not reported as "MEDIUM"
  // merely because SARIF's `level` only distinguishes error/warning/note.
  const cvssScoreText =
    sarifResult?.properties?.["security-severity"] ??
    sarifRule?.properties?.["security-severity"];
  const cvssScore = Number.parseFloat(String(cvssScoreText ?? ""));
  if (Number.isFinite(cvssScore)) {
    if (cvssScore >= 9.0) return "CRITICAL";
    if (cvssScore >= 7.0) return "HIGH";
    if (cvssScore >= 4.0) return "MEDIUM";
    return "LOW";
  }

  return severityFromSarifLevel(sarifResult?.level ?? sarifRule?.defaultConfiguration?.level);
}

/**
 * Strip a "file://" scheme and the workspace prefix from a SARIF URI.
 *
 * Note the scheme is `file://` (TWO slashes) followed by the path — so
 * `file:///repo/x` carries the absolute path `/repo/x`. Stripping three slashes
 * would eat the path's own leading slash and the workspace prefix would then
 * never match, leaving every path subtly wrong (`repo/x`) and unblameable.
 */
function toRepoRelativePath(sarifUri, projectRootPath) {
  if (!sarifUri) return null;
  let filePath = String(sarifUri).replace(/^file:\/\//, "").replace(/\\/g, "/");
  // A Windows drive path arrives from a file URI as "/C:/work/..." — drop the
  // synthetic leading slash so it compares against a real workspace root.
  if (/^\/[A-Za-z]:\//.test(filePath)) filePath = filePath.slice(1);
  const normalizedRoot = String(projectRootPath ?? "").replace(/\\/g, "/").replace(/\/$/, "");
  if (normalizedRoot && filePath.startsWith(normalizedRoot + "/")) {
    filePath = filePath.slice(normalizedRoot.length + 1);
  }
  return filePath.replace(/^\.\//, "");
}

/** Which of our tool names a SARIF driver name corresponds to. */
function toolNameFromDriver(driverName) {
  const lowercasedDriver = String(driverName ?? "").toLowerCase();
  if (lowercasedDriver.includes("gitleaks")) return "gitleaks";
  if (lowercasedDriver.includes("trivy")) return "trivy";
  if (lowercasedDriver.includes("dependency")) return "owasp-dependency-check";
  if (lowercasedDriver.includes("zap")) return "zap";
  if (lowercasedDriver.includes("sonar")) return "sonarqube";
  return "trivy";
}

/**
 * Normalize any SARIF document into findings.
 * @param {string} rawSarifText
 * @param {string} projectRootPath
 * @param {import('./types.mjs').SecurityToolName} [forcedToolName] Override when the driver name is unhelpful.
 * @returns {import('./types.mjs').SecurityFinding[]}
 */
export function normalizeSarif(rawSarifText, projectRootPath, forcedToolName) {
  const sarifDocument = JSON.parse(rawSarifText);
  /** @type {import('./types.mjs').SecurityFinding[]} */
  const findings = [];

  for (const sarifRun of sarifDocument?.runs ?? []) {
    const rulesById = indexRulesById(sarifRun);
    const toolName = forcedToolName ?? toolNameFromDriver(sarifRun?.tool?.driver?.name);

    for (const sarifResult of sarifRun?.results ?? []) {
      const ruleId = sarifResult?.ruleId ?? sarifResult?.rule?.id ?? "unknown-rule";
      const sarifRule = rulesById.get(ruleId);

      const primaryLocation = sarifResult?.locations?.[0]?.physicalLocation;
      const filePath = toRepoRelativePath(
        primaryLocation?.artifactLocation?.uri,
        projectRootPath,
      );
      const startLine = primaryLocation?.region?.startLine ?? null;

      // NOTE: region.snippet.text is deliberately NOT read — for gitleaks that
      // field contains the leaked secret itself.
      const messageText =
        sarifResult?.message?.text ??
        sarifRule?.shortDescription?.text ??
        ruleId;

      const helpText =
        sarifRule?.fullDescription?.text ??
        sarifRule?.help?.text ??
        "";

      const isSecretFinding = toolName === "gitleaks";

      findings.push(
        createFinding({
          tool: /** @type {any} */ (toolName),
          ruleId,
          severity: isSecretFinding ? "CRITICAL" : resolveSeverity(sarifResult, sarifRule),
          title: isSecretFinding
            ? `Secret detected: ${ruleId}`
            : String(messageText).split("\n")[0].slice(0, 200),
          detail: isSecretFinding
            ? "A credential matching this rule is present in the repository or its history. " +
              "The value is deliberately omitted from this report — read it from the scanner " +
              "artifact if you need to identify it. ROTATE THE CREDENTIAL FIRST: deleting the " +
              "line does not help, because the value remains in every clone of the history."
            : String(helpText || messageText).slice(0, 1200),
          filePath,
          startLine,
          fidelity: "exact",
          fingerprint:
            sarifResult?.partialFingerprints?.primaryLocationLineHash ??
            [toolName, ruleId, filePath ?? "", String(startLine ?? "")].join("|"),
        }),
      );
    }
  }

  return findings;
}

/**
 * Normalize actionlint's JSON output.
 *
 * actionlint is the highest-value linter in a GitHub Action repository: it
 * catches invalid workflow syntax, bad expressions and shell errors that would
 * otherwise only surface when a consumer's deploy fails at runtime.
 * @param {string} rawJsonText
 * @returns {import('./types.mjs').SecurityFinding[]}
 */
export function normalizeActionlint(rawJsonText) {
  const lintProblems = JSON.parse(rawJsonText);
  if (!Array.isArray(lintProblems)) return [];

  return lintProblems.map((lintProblem) =>
    createFinding({
      tool: "actionlint",
      ruleId: `actionlint/${lintProblem?.kind ?? "unknown"}`,
      severity: "MEDIUM",
      title: String(lintProblem?.message ?? "actionlint problem").slice(0, 200),
      detail:
        "Reported by actionlint. Workflow defects reach consumers as a failed deploy, " +
        "so they are treated as build problems rather than style nits.",
      filePath: String(lintProblem?.filepath ?? "").replace(/\\/g, "/") || null,
      startLine: lintProblem?.line ?? null,
      fingerprint: [
        "actionlint",
        lintProblem?.filepath ?? "",
        String(lintProblem?.line ?? ""),
        String(lintProblem?.kind ?? ""),
      ].join("|"),
    }),
  );
}

/**
 * Findings already produced in the shared shape (repo-rules, waf-lint).
 * @param {string} rawJsonText
 * @returns {import('./types.mjs').SecurityFinding[]}
 */
export function normalizePreNormalized(rawJsonText) {
  const parsedFindings = JSON.parse(rawJsonText);
  return Array.isArray(parsedFindings) ? parsedFindings : [];
}
