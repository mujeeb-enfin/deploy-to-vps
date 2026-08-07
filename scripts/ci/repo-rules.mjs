/**
 * scripts/ci/repo-rules.mjs — enforces the rules CONTRIBUTING.md already states
 * but nothing checked.
 *
 * CONTRIBUTING.md says, verbatim:
 *   - "Pin every `uses:` reference to a full 40-character commit SHA, not a tag."
 *   - "Pass all user-controlled values to the embedded script via `env:`, never
 *      by raw `${{ inputs.x }}` interpolation into `script: |`."
 *   - "Every input must have a `description`."
 *   - "Start with `set -euo pipefail`."
 *
 * A rule the code does not check is a suggestion. These are now checked.
 *
 * WHY THESE RULES AND NOT GENERIC LINTING: this repository is a PUBLIC composite
 * action that other people run inside their own CI with their own secrets. The
 * two rules that matter most here are supply-chain pinning and shell template
 * injection, because a defect in either is executed on somebody else's runner
 * with somebody else's credentials.
 *
 * NO YAML DEPENDENCY: these checks are line- and block-scalar based rather than
 * AST based, so the script stays dependency-free. actionlint and yamllint (both
 * already wired into CI) cover YAML validity; this covers policy.
 *
 * Usage:
 *   node scripts/ci/repo-rules.mjs --base=origin/main --out=reports/repo-rules.json
 */

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { createFinding, emitLog } from "./security/types.mjs";

const PROJECT_ROOT = process.cwd();
const COMPONENT = "repo_rules";

/** A `uses:` that is exempt from SHA pinning, with the reason. */
const PINNING_EXEMPT_PATTERNS = [
  // Self-reference in the EXAMPLE consumer workflows. Consumers are supposed to
  // use the floating major tag — that is the entire point of publishing `v1` —
  // so pinning these to a SHA would teach users the wrong thing.
  { pattern: /^mujeeb-enfin\/deploy-to-vps@/, reason: "self-reference in a consumer example" },
  // Local composite actions are part of this repository; there is no upstream
  // to pin against.
  { pattern: /^\.\//, reason: "local action in this repository" },
];

/**
 * Contexts that carry attacker-controllable text. Interpolating these directly
 * into a shell block lets a crafted value break out of the surrounding quotes
 * and execute arbitrary commands on the runner.
 */
const UNTRUSTED_EXPRESSION_CONTEXTS = [
  "inputs.",
  "github.event.",
  "github.head_ref",
];

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
 * Files changed by this pull request, relative to the merge base.
 * Returns null when the range cannot be resolved, so callers report everything
 * as pre-existing rather than blocking the world on a git failure.
 * @param {string} baseRef
 * @returns {string[]|null}
 */
export function listFilesChangedSinceBase(baseRef) {
  try {
    const diffOutput = execFileSync(
      "git",
      ["diff", "--name-only", "--diff-filter=ACMR", `${baseRef}...HEAD`],
      { encoding: "utf8", cwd: PROJECT_ROOT },
    );
    return diffOutput.split(/\r?\n/).map((changedPath) => changedPath.trim()).filter(Boolean);
  } catch (gitDiffError) {
    emitLog("warn", COMPONENT, "repo_rules_diff_unavailable", {
      baseRef,
      errorMessage: gitDiffError instanceof Error ? gitDiffError.message : String(gitDiffError),
      consequence: "All findings will be reported as pre-existing (non-blocking).",
    });
    return null;
  }
}

/**
 * Every YAML file that can contain workflow or action definitions.
 * @returns {string[]}
 */
export function listWorkflowFilePaths() {
  const candidatePaths = [];
  const workflowDirectory = path.join(PROJECT_ROOT, ".github", "workflows");
  if (existsSync(workflowDirectory)) {
    for (const fileName of readdirSync(workflowDirectory)) {
      if (fileName.endsWith(".yml") || fileName.endsWith(".yaml")) {
        candidatePaths.push(`.github/workflows/${fileName}`);
      }
    }
  }
  for (const actionFileName of ["action.yml", "action.yaml"]) {
    if (existsSync(path.join(PROJECT_ROOT, actionFileName))) candidatePaths.push(actionFileName);
  }
  return candidatePaths;
}

/**
 * Identify which lines sit inside a `run:` / `script:` block scalar, so shell
 * rules only inspect shell.
 * @param {string[]} fileLines
 * @returns {boolean[]} parallel array; true when that line is inside a shell block
 */
export function markShellBlockLines(fileLines) {
  const isShellLine = new Array(fileLines.length).fill(false);
  let blockIndent = null;

  for (let lineIndex = 0; lineIndex < fileLines.length; lineIndex += 1) {
    const currentLine = fileLines[lineIndex];

    if (blockIndent !== null) {
      if (currentLine.trim() === "") {
        isShellLine[lineIndex] = true;
        continue;
      }
      const currentIndent = currentLine.length - currentLine.trimStart().length;
      if (currentIndent > blockIndent) {
        isShellLine[lineIndex] = true;
        continue;
      }
      blockIndent = null;
    }

    const blockScalarMatch = /^(\s*)(run|script):\s*[|>]/.exec(currentLine);
    if (blockScalarMatch) blockIndent = blockScalarMatch[1].length;
  }

  return isShellLine;
}

/**
 * @param {{ruleId:string, severity:import('./security/types.mjs').FindingSeverity, title:string, detail:string, filePath:string, startLine:number|null}} input
 */
function createRepoRuleFinding(input) {
  return createFinding({
    tool: "repo-rules",
    ruleId: input.ruleId,
    severity: input.severity,
    title: input.title,
    detail: input.detail,
    filePath: input.filePath,
    startLine: input.startLine,
    fidelity: "exact",
    fingerprint: ["repo-rules", input.ruleId, input.filePath, String(input.startLine ?? "")].join("|"),
  });
}

// ── Rule 1: every third-party `uses:` pinned to a 40-character SHA ──────────

/**
 * @param {string} filePath
 * @param {string[]} fileLines
 */
function checkActionPinning(filePath, fileLines) {
  const findings = [];

  fileLines.forEach((currentLine, lineIndex) => {
    const usesMatch = /^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)/.exec(currentLine);
    if (!usesMatch) return;

    const usesReference = usesMatch[1];
    const exemption = PINNING_EXEMPT_PATTERNS.find(({ pattern }) => pattern.test(usesReference));
    if (exemption) return;

    const pinnedSha = usesReference.split("@")[1] ?? "";
    if (/^[0-9a-f]{40}$/.test(pinnedSha)) return;

    findings.push(
      createRepoRuleFinding({
        ruleId: "repo-rules/unpinned-action-reference",
        severity: "HIGH",
        title: `Unpinned action reference: ${usesReference}`,
        detail:
          "CONTRIBUTING.md: \"Pin every `uses:` reference to a full 40-character commit SHA, " +
          "not a tag.\" A tag is mutable — whoever controls the upstream repository can " +
          "repoint it at different code, which then runs on every consumer's runner with " +
          "their secrets. Resolve the SHA with:\n" +
          "    git ls-remote https://github.com/OWNER/REPO refs/tags/TAG\n" +
          "and keep the human-readable tag as a trailing comment.",
        filePath,
        startLine: lineIndex + 1,
      }),
    );
  });

  return findings;
}

// ── Rule 2: no untrusted `${{ }}` interpolation inside a shell block ────────

/**
 * @param {string} filePath
 * @param {string[]} fileLines
 */
function checkShellTemplateInjection(filePath, fileLines) {
  const findings = [];
  const isShellLine = markShellBlockLines(fileLines);

  fileLines.forEach((currentLine, lineIndex) => {
    if (!isShellLine[lineIndex]) return;
    if (!currentLine.includes("${{")) return;

    const matchedContext = UNTRUSTED_EXPRESSION_CONTEXTS.find((untrustedContext) =>
      new RegExp(`\\$\\{\\{[^}]*\\b${untrustedContext.replace(".", "\\.")}`).test(currentLine),
    );
    if (!matchedContext) return;

    findings.push(
      createRepoRuleFinding({
        ruleId: "repo-rules/shell-template-injection",
        severity: "CRITICAL",
        title: `Untrusted \`\${{ ${matchedContext}… }}\` interpolated directly into a shell block`,
        detail:
          "CONTRIBUTING.md: \"Pass all user-controlled values to the embedded script via " +
          "`env:`, never by raw `${{ inputs.x }}` interpolation into `script: |`.\"\n\n" +
          "GitHub substitutes the expression into the script BEFORE the shell parses it, so a " +
          "value containing a quote and a semicolon executes arbitrary commands on the runner. " +
          "In a public action that runner belongs to a consumer and holds their secrets.\n\n" +
          "Fix: add the value to the step's `env:` block and reference it as \"$VAR_NAME\" " +
          "inside the script, where the shell treats it as data rather than code.",
        filePath,
        startLine: lineIndex + 1,
      }),
    );
  });

  return findings;
}

// ── Rule 3: shell blocks are hardened ──────────────────────────────────────

/**
 * @param {string} filePath
 * @param {string} fileText
 */
function checkShellHardening(filePath, fileText) {
  if (!/^\s*(run|script):\s*[|>]/m.test(fileText)) return [];
  // Only the action's own embedded deploy script is long-lived enough to matter;
  // short summary steps in workflows are not worth the noise.
  if (!filePath.startsWith("action.y")) return [];
  if (fileText.includes("set -euo pipefail")) return [];

  return [
    createRepoRuleFinding({
      ruleId: "repo-rules/missing-shell-hardening",
      severity: "MEDIUM",
      title: `${filePath} has a shell block without \`set -euo pipefail\``,
      detail:
        "CONTRIBUTING.md: \"Start with `set -euo pipefail`.\" Without it a failing command in " +
        "the middle of a deploy is ignored and the action reports success on a half-finished " +
        "deployment.",
      filePath,
      startLine: null,
    }),
  ];
}

// ── Rule 4: every action input documents itself ────────────────────────────

/**
 * @param {string} filePath
 * @param {string[]} fileLines
 */
function checkInputDescriptions(filePath, fileLines) {
  if (!filePath.startsWith("action.y")) return [];

  const findings = [];
  let isInsideInputsBlock = false;
  let inputsBlockIndent = 0;

  for (let lineIndex = 0; lineIndex < fileLines.length; lineIndex += 1) {
    const currentLine = fileLines[lineIndex];
    if (currentLine.trim() === "" || currentLine.trim().startsWith("#")) continue;
    const currentIndent = currentLine.length - currentLine.trimStart().length;

    if (/^inputs:\s*$/.test(currentLine)) {
      isInsideInputsBlock = true;
      inputsBlockIndent = currentIndent;
      continue;
    }
    if (isInsideInputsBlock && currentIndent <= inputsBlockIndent) {
      isInsideInputsBlock = false;
      continue;
    }
    if (!isInsideInputsBlock) continue;

    const inputNameMatch = /^\s{2}([a-zA-Z_][a-zA-Z0-9_-]*):\s*$/.exec(currentLine);
    if (!inputNameMatch) continue;

    // Look ahead within this input's own block for a description key.
    let hasDescription = false;
    for (let lookAheadIndex = lineIndex + 1; lookAheadIndex < fileLines.length; lookAheadIndex += 1) {
      const lookAheadLine = fileLines[lookAheadIndex];
      if (lookAheadLine.trim() === "") continue;
      const lookAheadIndent = lookAheadLine.length - lookAheadLine.trimStart().length;
      if (lookAheadIndent <= currentIndent) break;
      if (/^\s*description:/.test(lookAheadLine)) {
        hasDescription = true;
        break;
      }
    }

    if (!hasDescription) {
      findings.push(
        createRepoRuleFinding({
          ruleId: "repo-rules/missing-input-description",
          severity: "LOW",
          title: `Action input "${inputNameMatch[1]}" has no description`,
          detail:
            "CONTRIBUTING.md: \"Every input must have a `description`. Be specific — it shows " +
            "up in the GitHub Marketplace UI.\"",
          filePath,
          startLine: lineIndex + 1,
        }),
      );
    }
  }

  return findings;
}

// ── Rule 5: every workflow declares least-privilege permissions ────────────

/**
 * @param {string} filePath
 * @param {string} fileText
 */
function checkWorkflowPermissions(filePath, fileText) {
  if (!filePath.startsWith(".github/workflows/")) return [];
  if (/^permissions:/m.test(fileText)) return [];

  return [
    createRepoRuleFinding({
      ruleId: "repo-rules/missing-workflow-permissions",
      severity: "MEDIUM",
      title: `${filePath} does not declare a \`permissions:\` block`,
      detail:
        "Without an explicit block the workflow inherits the repository default, which may grant " +
        "write scopes it never needs. Declare the narrowest set, e.g. `permissions: { contents: read }`.",
      filePath,
      startLine: 1,
    }),
  ];
}

// ── Orchestration ──────────────────────────────────────────────────────────

/**
 * Run every rule across every workflow and action file.
 * @returns {import('./security/types.mjs').SecurityFinding[]}
 */
export function runRepoRules() {
  const findings = [];

  for (const filePath of listWorkflowFilePaths()) {
    const fileText = readFileSync(path.join(PROJECT_ROOT, filePath), "utf8");
    const fileLines = fileText.split(/\r?\n/);

    findings.push(
      ...checkActionPinning(filePath, fileLines),
      ...checkShellTemplateInjection(filePath, fileLines),
      ...checkShellHardening(filePath, fileText),
      ...checkInputDescriptions(filePath, fileLines),
      ...checkWorkflowPermissions(filePath, fileText),
    );
  }

  return findings;
}

function main() {
  const outputPath = readCommandLineOption("out");
  const findings = runRepoRules();

  if (outputPath) {
    const resolvedOutputPath = path.resolve(PROJECT_ROOT, outputPath);
    mkdirSync(path.dirname(resolvedOutputPath), { recursive: true });
    writeFileSync(resolvedOutputPath, JSON.stringify(findings, null, 2), "utf8");
  }

  emitLog(findings.length > 0 ? "warn" : "info", COMPONENT, "repo_rules_completed", {
    findingCount: findings.length,
    outputPath,
  });

  for (const finding of findings) {
    process.stdout.write(
      `${finding.filePath}:${finding.startLine ?? "?"}  ${finding.ruleId} — ${finding.title}\n`,
    );
  }

  if (process.argv.includes("--exit-code") && findings.length > 0) process.exitCode = 1;
}

if (process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("repo-rules.mjs")) {
  try {
    main();
  } catch (repoRulesError) {
    emitLog("error", COMPONENT, "repo_rules_failed", {
      errorMessage: repoRulesError instanceof Error ? repoRulesError.message : String(repoRulesError),
    });
    process.exitCode = 1;
  }
}
