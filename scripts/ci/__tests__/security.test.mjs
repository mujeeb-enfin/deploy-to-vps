/**
 * Regression coverage for the security pipeline.
 *
 * Uses Node's BUILT-IN test runner (`node --test`) and `node:assert` — zero
 * dependencies, no package.json, nothing added to this action's supply chain.
 *
 * Run with:  node --test scripts/ci/__tests__/
 *
 * The properties guarded hardest:
 *   1. A leaked secret VALUE must never reach the pull-request comment. This is
 *      a PUBLIC repository — the comment is world-readable.
 *   2. Pre-existing findings must not block, or every pull request inherits the
 *      whole backlog and the gate gets switched off.
 *   3. An unpinned action must ALWAYS block, whoever introduced it.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { normalizeSarif, normalizeActionlint } from "../security/normalize.mjs";
import { decideBlockingFindings, countBlockingFindings } from "../security/verdict.mjs";
import { renderSecurityComment } from "../security/comment.mjs";
import { SECURITY_COMMENT_MARKER, normalizeSeverityWord } from "../security/types.mjs";
import { markShellBlockLines } from "../repo-rules.mjs";
import {
  evaluateAwsWafRequestShape,
  utf8ByteLength,
  AWS_WAF_QUERY_STRING_BYTE_LIMIT,
  AWS_WAF_BODY_BYTE_LIMIT,
} from "../waf/waf-lint.mjs";

const PULL_REQUEST_CONTEXT = {
  owner: "mujeeb-enfin",
  repo: "deploy-to-vps",
  pullNumber: 7,
  pullAuthorHandle: "pr-author",
  baseRef: "main",
};

function buildAttributedFinding(overrides = {}) {
  return {
    tool: "repo-rules",
    ruleId: "repo-rules/shell-template-injection",
    severity: "CRITICAL",
    title: "Untrusted expression in a shell block",
    detail: "detail",
    filePath: "action.yml",
    startLine: 323,
    requestUrl: null,
    hasFixAvailable: false,
    fixedVersion: null,
    fidelity: "exact",
    fingerprint: "fp-1",
    blameCommitSha: "abc1234def",
    blameAuthorName: "Mujeeb",
    blameGithubHandle: "mujeeb-enfin",
    wasIntroducedByThisPullRequest: true,
    isBlocking: false,
    ...overrides,
  };
}

// ── Secret safety ──────────────────────────────────────────────────────────

describe("gitleaks SARIF normalization — the secret value must never survive", () => {
  const LEAKED_SECRET_VALUE = "AKIAIOSFODNN7EXAMPLE";

  // gitleaks puts the matched credential in region.snippet.text. Our normalizer
  // must never read that field.
  const gitleaksSarif = JSON.stringify({
    runs: [
      {
        tool: { driver: { name: "gitleaks", rules: [{ id: "aws-access-token" }] } },
        results: [
          {
            ruleId: "aws-access-token",
            level: "error",
            message: { text: "aws-access-token detected" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "action.yml" },
                  region: { startLine: 12, snippet: { text: `key = "${LEAKED_SECRET_VALUE}"` } },
                },
              },
            ],
          },
        ],
      },
    ],
  });

  test("carries location and rule but not the secret", () => {
    const findings = normalizeSarif(gitleaksSarif, "/repo", "gitleaks");
    assert.equal(findings.length, 1);
    assert.equal(findings[0].filePath, "action.yml");
    assert.equal(findings[0].startLine, 12);
    assert.equal(findings[0].severity, "CRITICAL");
    assert.ok(!JSON.stringify(findings).includes(LEAKED_SECRET_VALUE));
  });

  test("does not leak the secret into the rendered comment either", () => {
    const findings = normalizeSarif(gitleaksSarif, "/repo", "gitleaks");
    const decided = decideBlockingFindings([
      buildAttributedFinding({ ...findings[0], wasIntroducedByThisPullRequest: true }),
    ]);
    const commentBody = renderSecurityComment(decided, PULL_REQUEST_CONTEXT, null);
    assert.ok(!commentBody.includes(LEAKED_SECRET_VALUE));
  });

  test("tells the developer to rotate, not merely delete the line", () => {
    // Deleting the line leaves the value in every clone of the history.
    assert.ok(normalizeSarif(gitleaksSarif, "/repo", "gitleaks")[0].detail.includes("ROTATE"));
  });
});

// ── SARIF normalization ────────────────────────────────────────────────────

describe("SARIF normalization", () => {
  test("maps CVSS security-severity onto real severity bands", () => {
    // SARIF `level` only has error/warning/note, so a CVSS 9.8 would otherwise
    // be reported as merely "HIGH" (or worse, MEDIUM).
    const trivySarif = JSON.stringify({
      runs: [
        {
          tool: {
            driver: {
              name: "Trivy",
              rules: [{ id: "CVE-2025-1", properties: { "security-severity": "9.8" } }],
            },
          },
          results: [
            {
              ruleId: "CVE-2025-1",
              level: "error",
              message: { text: "critical thing" },
              locations: [{ physicalLocation: { artifactLocation: { uri: "action.yml" } } }],
            },
          ],
        },
      ],
    });
    assert.equal(normalizeSarif(trivySarif, "/repo")[0].severity, "CRITICAL");
  });

  test("strips a file:/// prefix and the workspace root from the path", () => {
    const sarif = JSON.stringify({
      runs: [
        {
          tool: { driver: { name: "Trivy" } },
          results: [
            {
              ruleId: "R1",
              message: { text: "m" },
              locations: [
                { physicalLocation: { artifactLocation: { uri: "file:///repo/.github/workflows/zap.yml" } } },
              ],
            },
          ],
        },
      ],
    });
    assert.equal(normalizeSarif(sarif, "/repo")[0].filePath, ".github/workflows/zap.yml");
  });

  test("returns an empty list for a SARIF document with no results", () => {
    assert.deepEqual(normalizeSarif('{"runs":[]}', "/repo"), []);
  });

  test("normalizes actionlint problems with file and line", () => {
    const findings = normalizeActionlint(
      JSON.stringify([
        { message: "shellcheck reported issue", filepath: ".github/workflows/test.yml", line: 30, kind: "shellcheck" },
      ]),
    );
    assert.equal(findings[0].filePath, ".github/workflows/test.yml");
    assert.equal(findings[0].startLine, 30);
    assert.equal(findings[0].tool, "actionlint");
  });

  test("normalizeSeverityWord handles ZAP's compound riskdesc", () => {
    assert.equal(normalizeSeverityWord("Medium (High)"), "MEDIUM");
    assert.equal(normalizeSeverityWord("nonsense"), "INFO");
  });
});

// ── Tiered verdict ─────────────────────────────────────────────────────────

describe("verdict tiering", () => {
  test("blocks a secret this pull request introduced", () => {
    const decided = decideBlockingFindings([
      buildAttributedFinding({ tool: "gitleaks", wasIntroducedByThisPullRequest: true }),
    ]);
    assert.equal(decided[0].isBlocking, true);
  });

  test("does NOT block a pre-existing secret — that is a rotation task", () => {
    const decided = decideBlockingFindings([
      buildAttributedFinding({ tool: "gitleaks", wasIntroducedByThisPullRequest: false }),
    ]);
    assert.equal(decided[0].isBlocking, false);
  });

  test("ALWAYS blocks an unpinned action, even pre-existing", () => {
    // A mutable tag is exploitable by whoever controls it, independently of
    // which commit added the reference. Deferring it is exposure, not a control.
    const decided = decideBlockingFindings([
      buildAttributedFinding({
        tool: "repo-rules",
        ruleId: "repo-rules/unpinned-action-reference",
        wasIntroducedByThisPullRequest: false,
      }),
    ]);
    assert.equal(decided[0].isBlocking, true);
  });

  test("blocks CRITICAL/HIGH Trivy findings this PR introduced, not MEDIUM", () => {
    const high = decideBlockingFindings([
      buildAttributedFinding({ tool: "trivy", severity: "HIGH", wasIntroducedByThisPullRequest: true }),
    ]);
    const medium = decideBlockingFindings([
      buildAttributedFinding({ tool: "trivy", severity: "MEDIUM", wasIntroducedByThisPullRequest: true }),
    ]);
    assert.equal(high[0].isBlocking, true);
    assert.equal(medium[0].isBlocking, false);
  });

  test("never blocks on scanners that cannot gate this repository", () => {
    // Dependency-Check has no manifest to read here; ZAP scans a site not built
    // from this repo; SonarQube is a quality signal.
    const decided = decideBlockingFindings([
      buildAttributedFinding({ tool: "owasp-dependency-check", wasIntroducedByThisPullRequest: true }),
      buildAttributedFinding({ tool: "zap", wasIntroducedByThisPullRequest: true }),
      buildAttributedFinding({ tool: "sonarqube", wasIntroducedByThisPullRequest: true }),
      buildAttributedFinding({ tool: "waf-lint", wasIntroducedByThisPullRequest: true }),
    ]);
    assert.equal(countBlockingFindings(decided), 0);
  });
});

// ── Comment rendering ──────────────────────────────────────────────────────

describe("pull-request comment rendering", () => {
  test("embeds the marker so re-runs update one comment", () => {
    assert.ok(renderSecurityComment([], PULL_REQUEST_CONTEXT, null).includes(SECURITY_COMMENT_MARKER));
  });

  test("reports a clean pass when there are no findings", () => {
    assert.ok(renderSecurityComment([], PULL_REQUEST_CONTEXT, null).includes("Security checks passed"));
  });

  test("@-mentions the blamed developer", () => {
    const decided = decideBlockingFindings([buildAttributedFinding({ blameGithubHandle: "alice" })]);
    assert.ok(renderSecurityComment(decided, PULL_REQUEST_CONTEXT, null).includes("@alice"));
  });

  test("falls back to Unattributed rather than blaming the wrong person", () => {
    const decided = decideBlockingFindings([buildAttributedFinding({ blameGithubHandle: null })]);
    assert.ok(renderSecurityComment(decided, PULL_REQUEST_CONTEXT, null).includes("Unattributed"));
  });

  test("marks pre-existing findings and collapses advisories", () => {
    const decided = decideBlockingFindings([
      buildAttributedFinding({ tool: "zap", wasIntroducedByThisPullRequest: false }),
    ]);
    const commentBody = renderSecurityComment(decided, PULL_REQUEST_CONTEXT, null);
    assert.ok(commentBody.includes("(pre-existing)"));
    assert.ok(commentBody.includes("<details>"));
  });
});

// ── repo-rules shell block detection ───────────────────────────────────────

describe("shell block scalar detection", () => {
  test("marks only the lines inside a run:/script: block", () => {
    const fileLines = [
      "steps:",
      "  - name: a",
      "    run: |",
      "      echo one",
      "      echo two",
      "  - name: b",
      "    uses: foo/bar@sha",
    ];
    const isShellLine = markShellBlockLines(fileLines);
    assert.deepEqual(isShellLine, [false, false, false, true, true, false, false]);
  });

  test("treats a blank line inside a block as still inside it", () => {
    const isShellLine = markShellBlockLines(["    run: |", "      echo a", "", "      echo b", "  next: 1"]);
    assert.deepEqual(isShellLine, [false, true, true, true, false]);
  });
});

// ── AWS WAF portable core ──────────────────────────────────────────────────

describe("AWS WAF rule core", () => {
  test("allows a query string exactly at the limit and blocks one byte over", () => {
    const queryAtLimit = "a=" + "x".repeat(AWS_WAF_QUERY_STRING_BYTE_LIMIT - 2);
    assert.equal(utf8ByteLength(queryAtLimit), AWS_WAF_QUERY_STRING_BYTE_LIMIT);

    const atLimit = evaluateAwsWafRequestShape({ uriPath: "/x", rawQueryString: queryAtLimit });
    const overLimit = evaluateAwsWafRequestShape({ uriPath: "/x", rawQueryString: queryAtLimit + "y" });
    assert.ok(!atLimit.some((hit) => hit.ruleId === "SizeRestrictions_QUERYSTRING"));
    assert.ok(overLimit.some((hit) => hit.ruleId === "SizeRestrictions_QUERYSTRING"));
  });

  test("measures BYTES, not UTF-16 units", () => {
    // "é" is 2 bytes but length 1 — a String.length check would let a query
    // roughly twice the real limit through.
    const multiByteQuery = "a=" + "é".repeat(AWS_WAF_QUERY_STRING_BYTE_LIMIT / 2);
    assert.ok(multiByteQuery.length < AWS_WAF_QUERY_STRING_BYTE_LIMIT);
    assert.ok(utf8ByteLength(multiByteQuery) > AWS_WAF_QUERY_STRING_BYTE_LIMIT);
    assert.ok(
      evaluateAwsWafRequestShape({ uriPath: "/x", rawQueryString: multiByteQuery })
        .some((hit) => hit.ruleId === "SizeRestrictions_QUERYSTRING"),
    );
  });

  test("flags a scheme separator, including percent-encoded", () => {
    for (const rawQueryString of ["next=https://evil.test", "next=https%3A%2F%2Fevil.test"]) {
      assert.ok(
        evaluateAwsWafRequestShape({ uriPath: "/x", rawQueryString })
          .some((hit) => hit.ruleId === "GenericRFI_QUERYARGUMENTS"),
        `expected GenericRFI for ${rawQueryString}`,
      );
    }
  });

  test("does not flag an ordinary relative value", () => {
    assert.deepEqual(evaluateAwsWafRequestShape({ uriPath: "/x", rawQueryString: "next=/admin" }), []);
  });

  test("labels a credential-name inference as approximated, not exact", () => {
    const ruleHits = evaluateAwsWafRequestShape({ uriPath: "/x", rawQueryString: "token=abc" });
    assert.equal(ruleHits[0].fidelity, "approximated");
  });

  test("blocks a body over the 8 KB limit", () => {
    assert.ok(
      evaluateAwsWafRequestShape({
        uriPath: "/x",
        rawQueryString: "",
        bodyByteLength: AWS_WAF_BODY_BYTE_LIMIT + 1,
      }).some((hit) => hit.ruleId === "SizeRestrictions_BODY"),
    );
  });
});
