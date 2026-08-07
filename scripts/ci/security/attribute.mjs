/**
 * scripts/ci/security/attribute.mjs — answer "who wrote this line?" for a finding.
 *
 * The point of the whole gate: a finding that names nobody gets fixed by nobody.
 *
 * Attribution chain, in order:
 *   1. `git blame` the offending line            → commit SHA
 *   2. commit SHA → GitHub login via the REST API
 *   3. fall back to the pull-request author
 *   4. fall back to the unattributed section
 *
 * WHY THE API LOOKUP INSTEAD OF THE COMMIT EMAIL: a git email does not reliably
 * map to a GitHub account — noreply addresses, work/personal addresses and
 * squash-merge rewrites all break it. `GET /repos/{owner}/{repo}/commits/{sha}`
 * returns the account GitHub itself associated with the commit, which is the
 * only mapping that can be @-mentioned and actually notify a human.
 *
 * A WRONG attribution is worse than none — it blames an innocent colleague and
 * discredits the report — so every uncertain case falls through rather than
 * guessing.
 */

import { execFileSync } from "node:child_process";
import { emitLog } from "./types.mjs";

const COMPONENT = "security_attribution";

/**
 * Commits belonging to this pull request: `git rev-list <base>..HEAD`.
 *
 * On failure this returns an EMPTY set, which classifies every finding as
 * pre-existing and therefore non-blocking. That is the safe direction for a
 * false negative, but it SILENTLY DE-FANGS THE GATE — a shallow clone would
 * turn the whole check into a no-op that still reports green. So the failure is
 * logged at error level rather than swallowed: an un-gating CI must be visible.
 *
 * @param {string} baseRef
 * @param {string} projectRoot
 * @returns {Set<string>}
 */
export function listPullRequestCommitShas(baseRef, projectRoot) {
  try {
    const revListOutput = execFileSync("git", ["rev-list", `${baseRef}..HEAD`], {
      encoding: "utf8",
      cwd: projectRoot,
    });
    const commitShas = new Set(
      revListOutput.split(/\r?\n/).map((sha) => sha.trim()).filter(Boolean),
    );

    if (commitShas.size === 0) {
      emitLog("warn", COMPONENT, "pull_request_commit_range_empty", {
        baseRef,
        consequence:
          "No commits resolved between the base ref and HEAD, so nothing can be classified as " +
          "introduced by this pull request. Checks scoped to new findings will not block.",
        hint: "Confirm the checkout used fetch-depth: 0 and that the base ref was fetched.",
      });
    }
    return commitShas;
  } catch (revListError) {
    emitLog("error", COMPONENT, "pull_request_commit_range_unresolvable", {
      baseRef,
      errorMessage: revListError instanceof Error ? revListError.message : String(revListError),
      consequence:
        "Every finding will be treated as pre-existing, so newly-introduced secrets and rule " +
        "violations will NOT block this pull request. The gate is disabled for this run.",
      hint: "Almost always a shallow clone — the workflow must checkout with fetch-depth: 0.",
    });
    return new Set();
  }
}

/**
 * `git blame` a single line.
 * @param {string} projectRoot
 * @param {string} filePath
 * @param {number} lineNumber
 * @returns {{commitSha: string, authorName: string}|null}
 */
export function blameLine(projectRoot, filePath, lineNumber) {
  try {
    const blameOutput = execFileSync(
      "git",
      ["blame", "-L", `${lineNumber},${lineNumber}`, "--porcelain", "--", filePath],
      { encoding: "utf8", cwd: projectRoot },
    );

    const commitSha = blameOutput.split(/\s/)[0] ?? "";
    const authorLine = blameOutput
      .split(/\r?\n/)
      .find((outputLine) => outputLine.startsWith("author "));
    const authorName = authorLine ? authorLine.slice("author ".length).trim() : "";

    if (!/^[0-9a-f]{7,40}$/.test(commitSha)) return null;
    // An all-zero SHA means an uncommitted local change — not attributable to a
    // committed author, so fall through rather than blaming the last committer.
    if (/^0+$/.test(commitSha)) return null;

    return { commitSha, authorName };
  } catch {
    return null;
  }
}

/**
 * Resolve commit SHAs to GitHub logins, memoised — a pull request commonly has
 * many findings from the same few commits and the API is rate-limited.
 */
export class GithubHandleResolver {
  /**
   * @param {string} owner
   * @param {string} repo
   * @param {string|null} githubToken
   */
  constructor(owner, repo, githubToken) {
    this.owner = owner;
    this.repo = repo;
    this.githubToken = githubToken;
    /** @type {Map<string, string|null>} */
    this.handleByCommitSha = new Map();
  }

  /**
   * @param {string} commitSha
   * @returns {Promise<string|null>}
   */
  async resolveHandleForCommit(commitSha) {
    if (this.handleByCommitSha.has(commitSha)) {
      return this.handleByCommitSha.get(commitSha) ?? null;
    }
    if (!this.githubToken) {
      this.handleByCommitSha.set(commitSha, null);
      return null;
    }

    try {
      const commitResponse = await fetch(
        `https://api.github.com/repos/${this.owner}/${this.repo}/commits/${commitSha}`,
        {
          headers: {
            authorization: `Bearer ${this.githubToken}`,
            accept: "application/vnd.github+json",
            "user-agent": "deploy-to-vps-security-report",
          },
        },
      );
      if (!commitResponse.ok) {
        this.handleByCommitSha.set(commitSha, null);
        return null;
      }
      const commitPayload = await commitResponse.json();
      const resolvedHandle = commitPayload?.author?.login ?? null;
      this.handleByCommitSha.set(commitSha, resolvedHandle);
      return resolvedHandle;
    } catch {
      // A network failure must degrade to "unattributed", never crash the run —
      // a security report that fails to post is a security report nobody reads.
      this.handleByCommitSha.set(commitSha, null);
      return null;
    }
  }
}

/**
 * Attribute every finding. `isBlocking` stays false here; the tiering decision
 * belongs to ./verdict.mjs so it lives in one testable place.
 *
 * @param {import('./types.mjs').SecurityFinding[]} findings
 * @param {import('./types.mjs').PullRequestContext} pullRequestContext
 * @param {string} projectRoot
 * @param {GithubHandleResolver} handleResolver
 * @returns {Promise<import('./types.mjs').AttributedSecurityFinding[]>}
 */
export async function attributeFindings(
  findings,
  pullRequestContext,
  projectRoot,
  handleResolver,
) {
  const pullRequestCommitShas = listPullRequestCommitShas(
    `origin/${pullRequestContext.baseRef}`,
    projectRoot,
  );

  /** @type {import('./types.mjs').AttributedSecurityFinding[]} */
  const attributedFindings = [];

  for (const finding of findings) {
    const blameResult =
      finding.filePath && finding.startLine
        ? blameLine(projectRoot, finding.filePath, finding.startLine)
        : null;

    const wasIntroducedByThisPullRequest =
      blameResult !== null && pullRequestCommitShas.has(blameResult.commitSha);

    const blameGithubHandle = blameResult
      ? await handleResolver.resolveHandleForCommit(blameResult.commitSha)
      : null;

    attributedFindings.push({
      ...finding,
      blameCommitSha: blameResult?.commitSha ?? null,
      blameAuthorName: blameResult?.authorName ?? null,
      blameGithubHandle: blameGithubHandle ?? pullRequestContext.pullAuthorHandle,
      wasIntroducedByThisPullRequest,
      isBlocking: false,
    });
  }

  // Blame coverage is the health signal for this module. If it collapses,
  // findings pile silently into the "Unattributed" bucket and nobody is asked
  // to fix anything — the report still renders, so the failure is otherwise
  // invisible. Emit it every run, not only on total failure.
  const findingsNeedingBlameCount = attributedFindings.filter(
    (finding) => finding.filePath && finding.startLine,
  ).length;
  const blamedFindingCount = attributedFindings.filter(
    (finding) => finding.blameCommitSha !== null,
  ).length;

  emitLog(
    findingsNeedingBlameCount > 0 && blamedFindingCount === 0 ? "error" : "info",
    COMPONENT,
    "attribution_completed",
    {
      totalFindingCount: attributedFindings.length,
      findingsNeedingBlameCount,
      blamedFindingCount,
      introducedByThisPullRequestCount: attributedFindings.filter(
        (finding) => finding.wasIntroducedByThisPullRequest,
      ).length,
      pullRequestCommitCount: pullRequestCommitShas.size,
    },
  );

  return attributedFindings;
}
