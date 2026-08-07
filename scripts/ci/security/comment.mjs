/**
 * scripts/ci/security/comment.mjs — render the findings as one pull-request
 * comment and keep it updated in place.
 *
 * TWO THINGS THIS FILE EXISTS TO GET RIGHT:
 *
 * 1. ONE COMMENT, UPDATED. A 12-commit pull request must not accumulate 12
 *    security comments. Every render embeds SECURITY_COMMENT_MARKER; the upsert
 *    finds the existing comment by that marker and PATCHes it.
 *
 * 2. NO SECRET VALUES, EVER. The normalizer already refuses to read gitleaks'
 *    matched-text field, and nothing here reintroduces it. A pull-request
 *    comment is visible to everyone with repository access — and this is a
 *    PUBLIC repository, so that means everyone — and is copied into
 *    notification emails.
 */

import { SECURITY_COMMENT_MARKER } from "./types.mjs";

/** @type {Record<string,string>} */
const SEVERITY_ICON = {
  CRITICAL: "🔴",
  HIGH: "🔴",
  MEDIUM: "🟡",
  LOW: "🔵",
  INFO: "⚪",
};

/**
 * @param {import('./types.mjs').AttributedSecurityFinding} finding
 * @returns {string}
 */
function renderFindingLine(finding) {
  const severityIcon = SEVERITY_ICON[finding.severity] ?? "⚪";
  const locationLabel = finding.filePath
    ? `\`${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""}\``
    : (finding.requestUrl ?? "(no location)");
  const fidelityLabel = finding.fidelity === "approximated" ? " _(approximated)_" : "";
  const provenanceLabel = finding.wasIntroducedByThisPullRequest ? "" : " _(pre-existing)_";
  const commitLabel = finding.blameCommitSha
    ? ` — commit \`${finding.blameCommitSha.slice(0, 7)}\``
    : "";

  return (
    `- ${severityIcon} **${finding.tool}** \`${finding.ruleId}\` — ${finding.title} ` +
    `at ${locationLabel}${commitLabel}${fidelityLabel}${provenanceLabel}`
  );
}

/**
 * Group by the handle we will @-mention, so each developer sees their own list.
 * @param {import('./types.mjs').AttributedSecurityFinding[]} findings
 * @returns {Map<string, import('./types.mjs').AttributedSecurityFinding[]>}
 */
function groupFindingsByHandle(findings) {
  /** @type {Map<string, import('./types.mjs').AttributedSecurityFinding[]>} */
  const findingsByHandle = new Map();
  for (const finding of findings) {
    const groupKey = finding.blameGithubHandle ?? "__unattributed__";
    const existingGroup = findingsByHandle.get(groupKey);
    if (existingGroup) existingGroup.push(finding);
    else findingsByHandle.set(groupKey, [finding]);
  }
  return findingsByHandle;
}

/**
 * @param {string} handleKey
 * @param {number} blockingCount
 * @param {number} advisoryCount
 */
function renderHandleHeading(handleKey, blockingCount, advisoryCount) {
  const mention = handleKey === "__unattributed__" ? "Unattributed" : `@${handleKey}`;
  const countParts = [];
  if (blockingCount > 0) countParts.push(`${blockingCount} blocking`);
  if (advisoryCount > 0) countParts.push(`${advisoryCount} advisory`);
  return `### ${mention} — ${countParts.join(", ")}`;
}

/**
 * @param {import('./types.mjs').AttributedSecurityFinding[]} findings
 * @param {import('./types.mjs').PullRequestContext} pullRequestContext
 * @param {string|null} runUrl
 * @returns {string}
 */
export function renderSecurityComment(findings, pullRequestContext, runUrl) {
  const blockingFindings = findings.filter((finding) => finding.isBlocking);
  const advisoryFindings = findings.filter((finding) => !finding.isBlocking);

  const commentSections = [SECURITY_COMMENT_MARKER];

  if (findings.length === 0) {
    commentSections.push(
      "## ✅ Security checks passed",
      "",
      "gitleaks, Trivy, actionlint and the repository rules reported no findings on this " +
        "pull request.",
    );
    if (runUrl) commentSections.push("", `[Workflow run](${runUrl})`);
    return commentSections.join("\n");
  }

  commentSections.push(
    blockingFindings.length > 0
      ? `## ❌ Security checks failed — ${blockingFindings.length} blocking, ${advisoryFindings.length} advisory`
      : `## ✅ Security checks passed — ${advisoryFindings.length} advisory finding(s)`,
    "",
  );

  if (blockingFindings.length > 0) {
    commentSections.push(
      "These must be resolved before this pull request can merge. Each is attributed to the " +
        "developer whose commit last touched the line.",
      "",
    );
    for (const [handleKey, handleFindings] of groupFindingsByHandle(blockingFindings)) {
      commentSections.push(renderHandleHeading(handleKey, handleFindings.length, 0));
      for (const finding of handleFindings) commentSections.push(renderFindingLine(finding));
      commentSections.push("");
    }
  }

  if (advisoryFindings.length > 0) {
    commentSections.push(
      "<details>",
      `<summary>${advisoryFindings.length} advisory finding(s) — reported, not blocking</summary>`,
      "",
      "Pre-existing issues, lower-severity findings, and scanners that cannot gate this " +
        "repository (see docs/SECURITY_CI.md for why).",
      "",
    );
    for (const [handleKey, handleFindings] of groupFindingsByHandle(advisoryFindings)) {
      commentSections.push(renderHandleHeading(handleKey, 0, handleFindings.length));
      for (const finding of handleFindings) commentSections.push(renderFindingLine(finding));
      commentSections.push("");
    }
    commentSections.push("</details>", "");
  }

  commentSections.push(
    "---",
    "",
    "**Reading this report.** `(pre-existing)` means the blamed commit predates this pull " +
      "request — reported for visibility, not blocking. `(approximated)` marks a heuristic " +
      "rather than a proven condition. Secret VALUES are never printed here — read them from " +
      "the scanner artifact.",
    "",
    `Base branch: \`${pullRequestContext.baseRef}\`. See ` +
      "[docs/SECURITY_CI.md](docs/SECURITY_CI.md) for how to suppress a false positive properly.",
  );
  if (runUrl) commentSections.push("", `[Workflow run](${runUrl})`);

  return commentSections.join("\n");
}

/**
 * Create or update the security comment.
 * Returns false when the comment could not be posted — most commonly a fork
 * pull request, where GITHUB_TOKEN is read-only — so the caller can fall back
 * to the job summary rather than failing the run.
 *
 * @param {import('./types.mjs').PullRequestContext} pullRequestContext
 * @param {string} commentBody
 * @param {string|null} githubToken
 * @returns {Promise<boolean>}
 */
export async function upsertSecurityComment(pullRequestContext, commentBody, githubToken) {
  if (!githubToken) return false;

  const { owner, repo, pullNumber } = pullRequestContext;
  const requestHeaders = {
    authorization: `Bearer ${githubToken}`,
    accept: "application/vnd.github+json",
    "content-type": "application/json",
    "user-agent": "deploy-to-vps-security-report",
  };

  try {
    const listResponse = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/issues/${pullNumber}/comments?per_page=100`,
      { headers: requestHeaders },
    );
    if (!listResponse.ok) return false;

    const existingComments = await listResponse.json();
    const previousSecurityComment = (Array.isArray(existingComments) ? existingComments : []).find(
      (existingComment) => String(existingComment?.body ?? "").includes(SECURITY_COMMENT_MARKER),
    );

    const upsertResponse = previousSecurityComment
      ? await fetch(
          `https://api.github.com/repos/${owner}/${repo}/issues/comments/${previousSecurityComment.id}`,
          { method: "PATCH", headers: requestHeaders, body: JSON.stringify({ body: commentBody }) },
        )
      : await fetch(`https://api.github.com/repos/${owner}/${repo}/issues/${pullNumber}/comments`, {
          method: "POST",
          headers: requestHeaders,
          body: JSON.stringify({ body: commentBody }),
        });

    return upsertResponse.ok;
  } catch {
    // Never let a comment failure crash the run — the verdict is still enforced
    // through the exit code and the job summary.
    return false;
  }
}
