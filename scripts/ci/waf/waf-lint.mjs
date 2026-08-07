/**
 * scripts/ci/waf/waf-lint.mjs — AWS WAF request-shape rules.
 *
 * WHY THIS IS HERE AT ALL. This repository is a composite action: it has no
 * HTTP surface of its own, so most of a WAF linter has nothing to inspect. Two
 * things still make it worth carrying:
 *
 *   1. FORWARD-LOOKING CORE. `evaluateAwsWafRequestShape` implements the
 *      DOCUMENTED, DETERMINISTIC AWS managed-rule limits. The moment this action
 *      grows a callback URL, a webhook receiver, or a status endpoint, the rules
 *      are already here and already tested.
 *
 *   2. EXAMPLES ARE INSTRUCTIONS. A public action's README and workflow samples
 *      are copied verbatim into other people's pipelines. If an example shows a
 *      credential in a query string, that pattern propagates — and behind AWS
 *      WAF it also fails as a silent 403 that no application log can explain.
 *      So the linter checks the documentation this repo ships.
 *
 * FIDELITY. Findings are labelled. The byte-limit and `://` rules are `exact`
 * because AWS documents them precisely. Anything inferred from an argument's
 * NAME is `approximated` — the runtime value is not knowable from a document.
 *
 * Usage:
 *   node scripts/ci/waf/waf-lint.mjs --out=reports/waf-lint.json
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { createFinding, emitLog } from "../security/types.mjs";

const PROJECT_ROOT = process.cwd();
const COMPONENT = "waf_lint";

// ── Documented AWS WAF limits (AWSManagedRulesCommonRuleSet) ───────────────
// These are published, hard numbers — that is what makes the rules "exact".

/** `SizeRestrictions_QUERYSTRING` blocks a query string over this many bytes. */
export const AWS_WAF_QUERY_STRING_BYTE_LIMIT = 2048;
/** `SizeRestrictions_BODY` blocks a request body over this many bytes. */
export const AWS_WAF_BODY_BYTE_LIMIT = 8192;
/** `SizeRestrictions_URIPATH` blocks a URI path over this many bytes. */
export const AWS_WAF_URI_PATH_BYTE_LIMIT = 1024;

/** Query-argument names whose value is a credential. */
export const CREDENTIAL_ARGUMENT_NAMES = [
  "token", "key", "apikey", "api_key", "secret", "sig", "signature",
  "password", "passwd", "pwd", "access_token", "auth", "credential",
];

/** UTF-8 byte length. AWS measures bytes; `String.length` counts UTF-16 units. */
export function utf8ByteLength(candidateText) {
  return Buffer.byteLength(candidateText, "utf8");
}

/**
 * Evaluate the deterministic AWS managed rules against one request shape.
 * Portable core, kept independent of this repository's file layout.
 *
 * @param {{uriPath: string, rawQueryString: string, bodyByteLength?: number}} requestShape
 * @returns {{ruleId: string, fidelity: 'exact'|'approximated', title: string}[]}
 */
export function evaluateAwsWafRequestShape(requestShape) {
  const ruleHits = [];
  const { uriPath, rawQueryString, bodyByteLength = 0 } = requestShape;

  const queryStringByteLength = utf8ByteLength(rawQueryString);
  if (queryStringByteLength > AWS_WAF_QUERY_STRING_BYTE_LIMIT) {
    ruleHits.push({
      ruleId: "SizeRestrictions_QUERYSTRING",
      fidelity: "exact",
      title: `Query string is ${queryStringByteLength} bytes (AWS blocks over ${AWS_WAF_QUERY_STRING_BYTE_LIMIT})`,
    });
  }
  if (utf8ByteLength(uriPath) > AWS_WAF_URI_PATH_BYTE_LIMIT) {
    ruleHits.push({
      ruleId: "SizeRestrictions_URIPATH",
      fidelity: "exact",
      title: `URI path exceeds ${AWS_WAF_URI_PATH_BYTE_LIMIT} bytes`,
    });
  }
  if (bodyByteLength > AWS_WAF_BODY_BYTE_LIMIT) {
    ruleHits.push({
      ruleId: "SizeRestrictions_BODY",
      fidelity: "exact",
      title: `Request body exceeds ${AWS_WAF_BODY_BYTE_LIMIT} bytes`,
    });
  }

  for (const argumentPair of rawQueryString.split("&").filter(Boolean)) {
    const equalsIndex = argumentPair.indexOf("=");
    const argumentName = equalsIndex === -1 ? argumentPair : argumentPair.slice(0, equalsIndex);
    const argumentValue = equalsIndex === -1 ? "" : argumentPair.slice(equalsIndex + 1);

    let decodedValue = argumentValue;
    try {
      decodedValue = decodeURIComponent(argumentValue.replace(/\+/g, " "));
    } catch {
      // Malformed percent-encoding: AWS still inspects the raw bytes, and
      // throwing here would skip a request we are supposed to be checking.
    }

    if (decodedValue.includes("://")) {
      ruleHits.push({
        ruleId: "GenericRFI_QUERYARGUMENTS",
        fidelity: "exact",
        title: `Query argument "${argumentName}" contains "://"`,
      });
    }
    if (decodedValue.includes("../")) {
      ruleHits.push({
        ruleId: "GenericLFI_QUERYARGUMENTS",
        fidelity: "exact",
        title: `Query argument "${argumentName}" contains a path traversal sequence`,
      });
    }
    if (CREDENTIAL_ARGUMENT_NAMES.includes(argumentName.toLowerCase())) {
      ruleHits.push({
        ruleId: "SizeRestrictions_QUERYSTRING",
        fidelity: "approximated",
        title: `Query argument "${argumentName}" carries a credential`,
      });
    }
  }

  return ruleHits;
}

// ── Scanning this repository's documentation and examples ──────────────────

const SCANNED_FILE_EXTENSIONS = [".md", ".yml", ".yaml"];
const IGNORED_PATH_FRAGMENTS = ["node_modules", ".git/", "reports/", "CHANGELOG.md"];

/** @returns {string[]} repo-relative paths */
function listScannableFiles(directoryPath = PROJECT_ROOT) {
  /** @type {string[]} */
  const collectedPaths = [];
  const pendingDirectories = [directoryPath];

  while (pendingDirectories.length > 0) {
    const currentDirectory = pendingDirectories.pop();
    let directoryEntries;
    try {
      directoryEntries = readdirSync(currentDirectory);
    } catch {
      continue;
    }
    for (const entryName of directoryEntries) {
      const absoluteEntryPath = path.join(currentDirectory, entryName);
      const relativeEntryPath = path.relative(PROJECT_ROOT, absoluteEntryPath).replace(/\\/g, "/");
      if (IGNORED_PATH_FRAGMENTS.some((fragment) => relativeEntryPath.includes(fragment))) continue;
      if (entryName.startsWith(".") && entryName !== ".github") continue;

      let entryStats;
      try {
        entryStats = statSync(absoluteEntryPath);
      } catch {
        continue;
      }
      if (entryStats.isDirectory()) pendingDirectories.push(absoluteEntryPath);
      else if (SCANNED_FILE_EXTENSIONS.some((extension) => entryName.endsWith(extension))) {
        collectedPaths.push(relativeEntryPath);
      }
    }
  }
  return collectedPaths;
}

const URL_WITH_QUERY_PATTERN = /https?:\/\/[^\s"'`)<>]+\?[^\s"'`)<>]+/g;

/**
 * Scan the repository's shipped docs and examples for URL shapes that AWS WAF
 * would reject, so this action never teaches a pattern that silently 403s.
 * @returns {import('../security/types.mjs').SecurityFinding[]}
 */
export function runWafLint() {
  const findings = [];

  for (const filePath of listScannableFiles()) {
    const fileText = readFileSync(path.join(PROJECT_ROOT, filePath), "utf8");
    const fileLines = fileText.split(/\r?\n/);

    fileLines.forEach((currentLine, lineIndex) => {
      const matchedUrls = currentLine.match(URL_WITH_QUERY_PATTERN);
      if (!matchedUrls) return;

      for (const matchedUrl of matchedUrls) {
        const questionMarkIndex = matchedUrl.indexOf("?");
        const uriPath = matchedUrl.slice(0, questionMarkIndex);
        const rawQueryString = matchedUrl.slice(questionMarkIndex + 1);

        for (const ruleHit of evaluateAwsWafRequestShape({ uriPath, rawQueryString })) {
          findings.push(
            createFinding({
              tool: "waf-lint",
              ruleId: ruleHit.ruleId,
              severity: "LOW",
              title: `${ruleHit.title} (in a shipped example)`,
              detail:
                "This URL appears in documentation or a workflow example that consumers copy " +
                "verbatim. Behind AWS WAF the request is rejected before it reaches any " +
                "application, so it fails as a silent 403 with nothing in the logs. " +
                "Advisory only — this repository has no HTTP surface of its own.",
              filePath,
              startLine: lineIndex + 1,
              fidelity: ruleHit.fidelity,
              fingerprint: ["waf-lint", ruleHit.ruleId, filePath, String(lineIndex + 1)].join("|"),
            }),
          );
        }
      }
    });
  }

  return findings;
}

function main() {
  const outputArgument = process.argv.find((argument) => argument.startsWith("--out="));
  const outputPath = outputArgument ? outputArgument.slice("--out=".length) : null;
  const findings = runWafLint();

  if (outputPath) {
    const resolvedOutputPath = path.resolve(PROJECT_ROOT, outputPath);
    mkdirSync(path.dirname(resolvedOutputPath), { recursive: true });
    writeFileSync(resolvedOutputPath, JSON.stringify(findings, null, 2), "utf8");
  }

  emitLog(findings.length > 0 ? "warn" : "info", COMPONENT, "waf_lint_completed", {
    findingCount: findings.length,
    outputPath,
    scope: "documentation and workflow examples only — this repository has no HTTP surface",
  });

  for (const finding of findings) {
    process.stdout.write(
      `${finding.filePath}:${finding.startLine}  [${finding.fidelity}] ${finding.ruleId} — ${finding.title}\n`,
    );
  }
}

if (process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("waf-lint.mjs")) {
  try {
    main();
  } catch (wafLintError) {
    emitLog("error", COMPONENT, "waf_lint_failed", {
      errorMessage: wafLintError instanceof Error ? wafLintError.message : String(wafLintError),
    });
    process.exitCode = 1;
  }
}
