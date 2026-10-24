
import os
import re
import sys
from pathlib import Path

LOG_FILE = Path("failed-run.log")


def redact(text):
    patterns = [
        (
            r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*\S+",
            r"\1=[REDACTED]",
        ),
        (
            r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+",
            "Bearer [REDACTED]",
        ),
        (
            r"\bsk-[A-Za-z0-9_-]{12,}\b",
            "[REDACTED_API_KEY]",
        ),
    ]

    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)

    return text[-20000:]


RULES = [
    (
        "JavaScript Syntax Error",
        [
            "syntaxerror",
            "unexpected token",
            "missing ) after argument list",
            "unexpected end of input",
            "invalid or unexpected token",
            "unterminated string constant",
        ],
        "Node.js could not parse JavaScript source code.",
        "Check the reported file and line. Review brackets, parentheses, "
        "quotes and supported JavaScript syntax. Run node --check filename.js.",
    ),
    (
        "Node.js Version Incompatibility",
        [
            "ebadengine",
            "unsupported engine",
            "not compatible with your version of node",
            "requires a different node version",
        ],
        "A package may require a different Node.js runtime version.",
        "Compare the package's engines requirement with the Node.js version "
        "configured in the workflow. Select compatible supported versions.",
    ),
    (
        "Dependency Version Conflict",
        [
            "eresolve",
            "unable to resolve dependency tree",
            "peer dependency",
            "dependency conflict",
        ],
        "npm could not resolve compatible dependency versions.",
        "Review package.json and package-lock.json. Select compatible versions "
        "and rerun the tests before deploying.",
    ),
    (
        "Outdated or Deprecated Dependency",
        [
            "npm warn deprecated",
            "npm warn old lockfile",
            "npm outdated",
            "wanted",
            "latest",
        ],
        "The log may indicate a dependency update or deprecation issue.",
        "Review the dependency report and package maintenance status. "
        "Upgrade only after checking compatibility and running tests.",
    ),
    (
        "Missing or Incompatible Module",
        [
            "cannot find module",
            "err_module_not_found",
            "cannot find package",
            "module_not_found",
        ],
        "A module may be missing, imported incorrectly, or incompatible.",
        "Check import paths, package.json, package-lock.json and installation.",
    ),
    (
        "Automated Test Failure",
        [
            "err_assertion",
            "assertionerror",
            "test failed",
            "test failure",
            "not ok ",
        ],
        "A test assertion or expected result did not match actual behavior.",
        "Inspect the failing test and compare expected and actual values.",
    ),
    (
        "Permission or Authentication Failure",
        ["permission denied", "eacces", "unauthorized", "forbidden"],
        "A command or request may lack required permissions.",
        "Check repository permissions and token scopes. Never expose credentials.",
    ),
    (
        "Network or Timeout Failure",
        ["timed out", "timeout", "connection refused", "enotfound"],
        "A network operation or service connection may have failed.",
        "Check DNS, network access, service health and timeout settings.",
    ),
]


def analyze(log):
    lines = log.splitlines()

    # Prioritize specific errors over generic dependency report headings.
    for category, patterns, cause, fix in RULES:
        matches = [
            line.strip()
            for line in lines
            if any(pattern in line.lower() for pattern in patterns)
        ]

        if matches:
            evidence = "\n".join(
                f"- `{line[:400]}`" for line in matches[-5:]
            )

            return (
                f"## Failure Analysis\n\n"
                f"**Category:** {category}\n\n"
                f"**Likely cause:** {cause}\n\n"
                f"**Evidence:**\n{evidence}\n\n"
                f"**Recommended fix:** {fix}\n\n"
                "**Note:** This is a pattern-based diagnosis. Verify the "
                "suspected cause against the failed step and full logs.\n"
            )

    tail = "\n".join(lines[-12:])[-3000:]

    return (
        "## Failure Analysis\n\n"
        "**Category:** Unknown Failure\n\n"
        "**Likely cause:** No known error pattern was detected.\n\n"
        f"**Recent log lines:**\n```\n{tail}\n```\n\n"
        "Review the first meaningful error in the failed workflow step.\n"
    )


def main():
    if not LOG_FILE.exists():
        raise RuntimeError("failed-run.log was not downloaded.")

    log = redact(
        LOG_FILE.read_text(encoding="utf-8", errors="replace")
    )
    report = analyze(log)

    print(report)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write("# Automatic CI Failure Report\n\n")
            summary.write(report + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Analyzer failed: {exc}", file=sys.stderr)
        sys.exit(1)
