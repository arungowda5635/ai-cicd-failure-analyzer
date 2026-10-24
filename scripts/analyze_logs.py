
import os
import re
import sys
from pathlib import Path

LOG_FILE = Path("failed-run.log")
MAX_LOG_CHARS = 20000
MAX_EVIDENCE_PER_CATEGORY = 10
MAX_UNCLASSIFIED_LINES = 50


def redact(text):
    """Basic redaction of common credential patterns."""
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

    return text[-MAX_LOG_CHARS:]


# Categories are evaluated independently so multiple errors can be reported.
RULES = [
    {
        "category": "JavaScript Syntax Error",
        "patterns": [
            r"\bSyntaxError\b",
            r"unexpected token",
            r"missing \) after argument list",
            r"unexpected end of input",
            r"invalid or unexpected token",
            r"unterminated string constant",
        ],
        "cause": "Node.js could not parse JavaScript source code.",
        "fix": (
            "Check the file and line number in the log. Review brackets, "
            "parentheses, quotes, operators and supported JavaScript syntax. "
            "Run node --check path/to/file.js."
        ),
    },
    {
        "category": "Missing Dependency or Module",
        "patterns": [
            r"module_not_found",
            r"cannot find module",
            r"cannot find package",
            r"no module named ",
            r"\bmodulenotfounderror\b",
            r"\bimporterror\b",
            r"err_module_not_found",
        ],
        "cause": (
            "A package or module could not be resolved. It may be missing, "
            "incorrectly imported or unavailable in the current environment."
        ),
        "fix": (
            "Check the package name, import path, package.json or Python "
            "requirements file. Verify the correct runtime's dependencies "
            "are installed before running tests."
        ),
    },
    {
        "category": "Unknown or Unavailable npm Package",
        "patterns": [
            r"\bE404\b",
            r"npm error 404",
            r"npm err! 404",
            r"not found in this registry",
            r"is not in this registry",
        ],
        "cause": (
            "npm could not find the requested package or version in the "
            "configured registry."
        ),
        "fix": (
            "Verify the package name and version, registry URL, and access "
            "to any private registry. A 404 does not always mean the package "
            "does not exist."
        ),
    },
    {
        "category": "Node.js Version Incompatibility",
        "patterns": [
            r"\bEBADENGINE\b",
            r"unsupported engine",
            r"not compatible with your version of node",
            r"requires a different node version",
        ],
        "cause": (
            "A package may require a different Node.js version from the "
            "version used by the CI workflow."
        ),
        "fix": (
            "Compare the package's engines requirement with the Node.js "
            "version configured in GitHub Actions. Select compatible, "
            "supported versions."
        ),
    },
    {
        "category": "Dependency Version Conflict",
        "patterns": [
            r"\bERESOLVE\b",
            r"unable to resolve dependency tree",
            r"peer dep missing",
            r"conflicting peer dependency",
            r"dependency conflict",
        ],
        "cause": (
            "The package manager could not resolve a compatible set "
            "of dependency versions."
        ),
        "fix": (
            "Review package.json, the lockfile and peer dependency "
            "requirements. Select compatible versions and rerun tests."
        ),
    },
    {
        "category": "Deprecated Dependency",
        "patterns": [
            r"npm warn deprecated",
            r"npm WARN deprecated",
            r"npm warn old lockfile",
        ],
        "cause": (
            "A dependency may be deprecated or the lockfile may use an "
            "older format. A warning alone does not prove build failure."
        ),
        "fix": (
            "Review package maintenance status and supported versions. "
            "Plan a compatible upgrade and run tests before deployment."
        ),
    },
    {
        "category": "Type or Reference Error",
        "patterns": [
            r"\bTypeError\b",
            r"\bReferenceError\b",
            r"\bRangeError\b",
        ],
        "cause": (
            "The program encountered an invalid operation, undefined "
            "reference or out-of-range value."
        ),
        "fix": (
            "Inspect the stack trace and referenced file and line. Check "
            "variable names, types, input values and function arguments."
        ),
    },
    {
        "category": "Automated Test Failure",
        "patterns": [
            r"\bAssertionError\b",
            r"\bERR_ASSERTION\b",
            r"\btest failed\b",
            r"\btest failure\b",
            r"^\s*not ok\b",
        ],
        "cause": (
            "A test assertion failed or the observed behavior did not "
            "match the expected result."
        ),
        "fix": (
            "Inspect the failing test and compare expected and actual "
            "values. Fix the underlying code or correct the test if "
            "its expectation is wrong."
        ),
    },
    {
        "category": "Permission or Authentication Failure",
        "patterns": [
            r"permission denied",
            r"\bEACCES\b",
            r"\bEPERM\b",
            r"\bunauthorized\b",
            r"\bforbidden\b",
            r"\b401\b",
            r"\b403\b",
        ],
        "cause": (
            "A command or request may lack required permissions or "
            "valid authentication."
        ),
        "fix": (
            "Check repository permissions, token scopes and service "
            "credentials. Never print credentials in logs."
        ),
    },
    {
        "category": "Network or Timeout Failure",
        "patterns": [
            r"timed out",
            r"\btimeout\b",
            r"connection refused",
            r"\bENOTFOUND\b",
            r"\bECONNRESET\b",
            r"\bECONNREFUSED\b",
        ],
        "cause": (
            "A network operation, DNS lookup or service connection "
            "may have failed."
        ),
        "fix": (
            "Check DNS, network access, service health, endpoint settings "
            "and timeout configuration."
        ),
    },
    {
        "category": "Build or Command Failure",
        "patterns": [
            r"npm error",
            r"npm err!",
            r"process completed with exit code [1-9]",
            r"command failed",
            r"\bBUILD FAILED\b",
        ],
        "cause": (
            "A build or command exited unsuccessfully. This may be a "
            "secondary symptom of an earlier error."
        ),
        "fix": (
            "Review earlier log lines to find the first meaningful error "
            "before the final command failure."
        ),
    },
]


GENERIC_ERROR_PATTERNS = [
    r"\bSyntaxError\b",
    r"\bTypeError\b",
    r"\bReferenceError\b",
    r"\bRangeError\b",
    r"\bModuleNotFoundError\b",
    r"\bImportError\b",
    r"\bError:",
    r"\bERR_[A-Z0-9_]+\b",
    r"\bE[A-Z0-9]{3,}\b",
    r"\bFATAL\b",
    r"\bFAILED\b",
    r"\bFAILURE\b",
    r"\bException\b",
    r"Traceback \(most recent call last\)",
    r"^\s*not ok\b",
]


def analyze(log):
    lines = log.splitlines()
    findings = []
    reported_evidence = set()

    for rule in RULES:
        matching_lines = []

        for line in lines:
            clean_line = line.strip()
            if not clean_line:
                continue

            if any(
                re.search(pattern, clean_line, re.IGNORECASE)
                for pattern in rule["patterns"]
            ):
                if clean_line not in matching_lines:
                    matching_lines.append(clean_line)

        if matching_lines:
            evidence = matching_lines[-MAX_EVIDENCE_PER_CATEGORY:]
            reported_evidence.update(evidence)

            findings.append({
                "category": rule["category"],
                "cause": rule["cause"],
                "fix": rule["fix"],
                "evidence": evidence,
                "total_matches": len(matching_lines),
            })

    # Collect error-like lines not already reported as evidence.
    unclassified = []
    seen_lines = set()

    for line in lines:
        clean_line = line.strip()

        if not clean_line or clean_line in seen_lines:
            continue

        seen_lines.add(clean_line)

        looks_like_error = any(
            re.search(pattern, clean_line, re.IGNORECASE)
            for pattern in GENERIC_ERROR_PATTERNS
        )

        if looks_like_error and clean_line not in reported_evidence:
            unclassified.append(clean_line)

    report = [
        "# CI/CD Failure Analysis",
        "",
        "**Analysis mode:** Rule-based (no API required)",
        "",
        f"**Detected error categories:** {len(findings)}",
        "",
        "> Findings are based on log patterns. Some errors may be secondary "
        "symptoms of an earlier failure.",
        "",
    ]

    if findings:
        for index, finding in enumerate(findings, start=1):
            report.extend([
                f"## {index}. {finding['category']}",
                "",
                f"**Likely cause:** {finding['cause']}",
                "",
                f"**Matching log lines:** {finding['total_matches']}",
                "",
                "**Evidence from the log:**",
                "",
            ])

            for evidence in finding["evidence"]:
                safe_evidence = evidence[:500].replace("`", "'")
                report.append(f"- `{safe_evidence}`")

            if finding["total_matches"] > MAX_EVIDENCE_PER_CATEGORY:
                report.append(
                    f"- Showing the latest {MAX_EVIDENCE_PER_CATEGORY} "
                    "matching lines."
                )

            report.extend([
                "",
                f"**Recommended fix:** {finding['fix']}",
                "",
            ])
    else:
        report.extend([
            "No known error categories matched the downloaded log.",
            "",
            "Review the original failed step and the unclassified "
            "error lines below.",
            "",
        ])

    report.extend([
        "## Other / Unclassified Errors",
        "",
    ])

    if unclassified:
        for line in unclassified[:MAX_UNCLASSIFIED_LINES]:
            safe_line = line[:500].replace("`", "'")
            report.append(f"- `{safe_line}`")

        if len(unclassified) > MAX_UNCLASSIFIED_LINES:
            report.append(
                f"- Plus {len(unclassified) - MAX_UNCLASSIFIED_LINES} "
                "additional error-like lines."
            )
    else:
        report.append(
            "No additional unclassified error patterns were detected."
        )

    report.extend([
        "",
        "## Verification",
        "",
        "Review each finding against the original failed step. Resolve the "
        "earliest root cause first, then rerun the failed workflow and "
        "confirm that the relevant checks pass.",
    ])

    return "\n".join(report) + "\n"


def main():
    if not LOG_FILE.is_file():
        raise FileNotFoundError(
            f"{LOG_FILE} was not found. Check the log-download step."
        )

    original_log = LOG_FILE.read_text(
        encoding="utf-8",
        errors="replace",
    )

    log = redact(original_log)
    report = analyze(log)

    # Print the full report into the GitHub Actions step log.
    print(report, flush=True)

    # Publish the report to the GitHub Actions Summary.
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(report + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            f"Analyzer failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)
