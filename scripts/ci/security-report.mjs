/**
 * scripts/ci/security-report.mjs — the ONLY thing that fails a pull request.
 *
 * Every scanner job is configured to exit 0 and drop a report. This script
 * collects those reports, normalizes them, blames each finding on the developer
 * who wrote the line, posts one consolidated comment, and sets the exit code.
 *
 * That gives branch protection ONE required status check instead of six, and
 * puts the tiering rule in one testable function (./security/verdict.mjs).
 *
 * A MISSING report is fine — that scanner did not run. An UNPARSEABLE report is
 * a hard failure: silently treating a broken scanner as "no findings" is how a
 * security gate becomes decorative.
 *
 * Usage:
 *   node scripts/ci/security-report.mjs \
 *     --gitleaks-sarif=reports/gitleaks.sarif \
 *     --trivy-sarif=reports/trivy-fs.sarif \
 *     --actionlint=reports/actionlint.json \
 *     --repo-rules=reports/repo-rules.json
 */

import { readFileSync, existsSync, appendFileSync } from "node:fs";
import path from "node:path";
import { emitLog } from "./security/types.mjs";
import {
  normalizeSarif,
  normalizeActionlint,
  normalizePreNormalized,
} from "./security/normalize.mjs";
import { attributeFindings, GithubHandleResolver } from "./security/attribute.mjs";
import { decideBlockingFindings, countBlockingFindings } from "./security/verdict.mjs";
import { renderSecurityComment, upsertSecurityComment } from "./security/comment.mjs";

const PROJECT_ROOT = process.cwd();
const COMPONENT = "security_report";

/**
 * @param {string} optionName
 * @returns {string|null}
 */
function readCommandLineOption(optionName) {
  const optionPrefix = `--${optionName}=`;
  const matchedArgument = process.argv.find((argument) => argument.startsWith(optionPrefix));
  return matchedArgument ? matchedArgument.slice(optionPrefix.length) : null;
}

/**
 * Load one scanner report.
 * - absent / empty → null (that scanner did not run)
 * - present but unparseable → throws (a broken scanner must not look clean)
 * @param {string} optionName
 * @returns {string|null}
 */
function loadScannerReport(optionName) {
  const reportPath = readCommandLineOption(optionName);
  if (!reportPath) return null;

  const resolvedPath = path.resolve(PROJECT_ROOT, reportPath);
  if (!existsSync(resolvedPath)) {
    emitLog("info", COMPONENT, "security_report_absent", { optionName, reportPath });
    return null;
  }
  const reportText = readFileSync(resolvedPath, "utf8").trim();
  if (reportText === "") {
    emitLog("info", COMPONENT, "security_report_empty", { optionName, reportPath });
    return null;
  }
  return reportText;
}

/**
 * @param {string} optionName
 * @param {(rawText: string) => import('./security/types.mjs').SecurityFinding[]} normalizeReport
 */
function collectFindings(optionName, normalizeReport) {
  const reportText = loadScannerReport(optionName);
  if (reportText === null) return [];

  try {
    const findings = normalizeReport(reportText);
    emitLog("info", COMPONENT, "security_report_normalized", {
      optionName,
      findingCount: findings.length,
    });
    return findings;
  } catch (normalizeError) {
    // Re-thrown: a scanner whose output we cannot read is an UNKNOWN, and an
    // unknown must never be rendered as a pass.
    emitLog("error", COMPONENT, "security_report_unparseable", {
      optionName,
      errorMessage: normalizeError instanceof Error ? normalizeError.message : String(normalizeError),
    });
    throw normalizeError;
  }
}

/** Read the pull-request context from the Actions event payload. */
function resolvePullRequestContext() {
  const [owner, repo] = String(process.env.GITHUB_REPOSITORY ?? "").split("/");
  if (!owner || !repo) return null;

  const eventPayloadPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPayloadPath || !existsSync(eventPayloadPath)) return null;

  try {
    const eventPayload = JSON.parse(readFileSync(eventPayloadPath, "utf8"));
    const pullRequest = eventPayload?.pull_request;
    if (!pullRequest?.number) return null;

    return {
      owner,
      repo,
      pullNumber: pullRequest.number,
      pullAuthorHandle: pullRequest?.user?.login ?? null,
      baseRef: pullRequest?.base?.ref ?? "main",
    };
  } catch (eventParseError) {
    emitLog("error", COMPONENT, "security_event_payload_unreadable", {
      errorMessage: eventParseError instanceof Error ? eventParseError.message : String(eventParseError),
    });
    return null;
  }
}

/** @param {string} commentBody */
function writeJobSummary(commentBody) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  try {
    appendFileSync(summaryPath, commentBody + "\n", "utf8");
  } catch (summaryWriteError) {
    emitLog("warn", COMPONENT, "security_job_summary_write_failed", {
      errorMessage: summaryWriteError instanceof Error ? summaryWriteError.message : String(summaryWriteError),
    });
  }
}

function collectAllFindings() {
  return [
    ...collectFindings("gitleaks-sarif", (rawText) => normalizeSarif(rawText, PROJECT_ROOT, "gitleaks")),
    ...collectFindings("trivy-sarif", (rawText) => normalizeSarif(rawText, PROJECT_ROOT, "trivy")),
    ...collectFindings("owasp-sarif", (rawText) =>
      normalizeSarif(rawText, PROJECT_ROOT, "owasp-dependency-check"),
    ),
    ...collectFindings("zap-sarif", (rawText) => normalizeSarif(rawText, PROJECT_ROOT, "zap")),
    ...collectFindings("actionlint", normalizeActionlint),
    ...collectFindings("repo-rules", normalizePreNormalized),
    ...collectFindings("waf-lint", normalizePreNormalized),
  ];
}

/**
 * Drop repeats of the same defect reported by overlapping scanners.
 * @param {import('./security/types.mjs').SecurityFinding[]} findings
 */
function dedupeByFingerprint(findings) {
  const findingByFingerprint = new Map();
  for (const finding of findings) {
    if (!findingByFingerprint.has(finding.fingerprint)) {
      findingByFingerprint.set(finding.fingerprint, finding);
    }
  }
  return [...findingByFingerprint.values()];
}

async function main() {
  const allFindings = dedupeByFingerprint(collectAllFindings());
  const pullRequestContext = resolvePullRequestContext();

  if (!pullRequestContext) {
    // Outside a pull request (local run, or a push build). Report what was
    // found, attribute nothing, do not fail — there is no diff to scope against
    // so every finding would look pre-existing anyway.
    emitLog("warn", COMPONENT, "security_report_no_pull_request_context", {
      findingCount: allFindings.length,
      consequence: "Reported without attribution; exit code not set.",
    });
    for (const finding of allFindings) {
      process.stdout.write(
        `${finding.filePath ?? finding.requestUrl ?? "(no location)"}:${finding.startLine ?? "?"}  ` +
          `${finding.tool} ${finding.ruleId} — ${finding.title}\n`,
      );
    }
    return;
  }

  const githubToken = process.env.GITHUB_TOKEN ?? null;
  const handleResolver = new GithubHandleResolver(
    pullRequestContext.owner,
    pullRequestContext.repo,
    githubToken,
  );

  const attributedFindings = decideBlockingFindings(
    await attributeFindings(allFindings, pullRequestContext, PROJECT_ROOT, handleResolver),
  );

  const runUrl =
    process.env.GITHUB_SERVER_URL && process.env.GITHUB_RUN_ID
      ? `${process.env.GITHUB_SERVER_URL}/${pullRequestContext.owner}/${pullRequestContext.repo}/actions/runs/${process.env.GITHUB_RUN_ID}`
      : null;

  const commentBody = renderSecurityComment(attributedFindings, pullRequestContext, runUrl);
  const wasCommentPosted = await upsertSecurityComment(pullRequestContext, commentBody, githubToken);

  if (!wasCommentPosted) {
    // Most commonly a fork pull request, where GITHUB_TOKEN is read-only.
    // Degrade to the job summary rather than failing the run — the verdict is
    // still enforced by the exit code below.
    emitLog("warn", COMPONENT, "security_comment_post_failed", {
      consequence: "Findings written to the job summary instead.",
    });
    writeJobSummary(commentBody);
  }

  const blockingCount = countBlockingFindings(attributedFindings);
  emitLog(blockingCount > 0 ? "error" : "info", COMPONENT, "security_report_completed", {
    pullNumber: pullRequestContext.pullNumber,
    totalFindingCount: attributedFindings.length,
    blockingFindingCount: blockingCount,
    advisoryFindingCount: attributedFindings.length - blockingCount,
    wasCommentPosted,
  });

  if (blockingCount > 0) process.exitCode = 1;
}

if (process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("security-report.mjs")) {
  main().catch((reportError) => {
    emitLog("error", COMPONENT, "security_report_failed", {
      errorMessage: reportError instanceof Error ? reportError.message : String(reportError),
    });
    process.exitCode = 1;
  });
}
