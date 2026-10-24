
import os
import re
import sys
from pathlib import Path

LOG_FILE = Path("sample_logs/build_failure.log")


def redact_secrets(text):
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

    return text[:12000]


def analyze_failure(log_text):
    checks = [
        (
            ["modulenotfounderror", "no module named",
             "cannot find module", "module not found"],
            "Missing dependency",
            "A required package or module may not be installed.",
            "Check the dependency manifest and ensure the workflow "
            "installs the required dependencies before running tests.",
        ),
        (
            ["permission denied", "access is denied",
             "eacces", "unauthorized", "forbidden"],
            "Permission or authentication failure",
            "The job may lack permissions or valid credentials.",
            "Check repository permissions, token scopes, and secret "
            "configuration. Do not print credentials in logs.",
        ),
        (
            ["timed out", "timeout", "connection refused",
             "could not resolve host", "network is unreachable"],
            "Timeout or connectivity failure",
            "A network request or operation may have timed out.",
            "Check service availability, DNS, network routes, firewall "
            "rules, and timeout settings.",
        ),
        (
            ["assertionerror", "test failed", "tests failed",
             "failed tests", "test failure"],
            "Test failure",
            "A test assertion or test case may have failed.",
            "Review the failing test, expected versus actual values, "
            "and recent application changes.",
        ),
        (
            ["no such file or directory", "file not found",
             "cannot find the path"],
            "Missing file or path",
            "A required file or configured path may be unavailable.",
            "Verify the file exists in the repository and check working "
            "directories and filename casing.",
        ),
        (
            ["failed to pull image", "imagepullbackoff",
             "manifest unknown", "pull access denied"],
            "Container image failure",
            "The image may not exist or the registry may reject access.",
            "Verify the image name and tag, registry availability, "
            "and required pull permissions.",
        ),
        (
            ["exit code 1", "build failed", "compilation failed"],
            "Build or command failure",
            "A build command returned a failure status.",
            "Inspect the preceding log lines for the original error "
            "and verify the build command and configuration.",
        ),
    ]

    lower_log = log_text.lower()

    for keywords, category, cause, fix in checks:
        if any(keyword in lower_log for keyword in keywords):
            evidence = [
                line.strip()
                for line in log_text.splitlines()
                if any(keyword in line.lower() for keyword in keywords)
            ]

            return {
                "category": category,
                "cause": cause,
                "evidence": evidence[:5],
                "fix": fix,
            }

    return {
        "category": "Unknown failure",
        "cause": "No known error pattern was detected.",
        "evidence": log_text.splitlines()[-5:],
        "fix": "Review the full log and identify the first meaningful "
               "error before the final failure message.",
    }


def main():
    if not LOG_FILE.is_file():
        raise RuntimeError(f"Log file not found: {LOG_FILE}")

    log_text = redact_secrets(
        LOG_FILE.read_text(encoding="utf-8", errors="replace")
    )

    result = analyze_failure(log_text)

    report = [
        "# CI/CD Failure Analysis",
        "",
        "**Analysis mode:** Rule-based (no API required)",
        "",
        f"**Failure category:** {result['category']}",
        "",
        f"**Likely cause:** {result['cause']}",
        "",
        "**Evidence from the log:**",
    ]

    report.extend(
        f"- `{line}`" for line in result["evidence"]
    )

    report.extend([
        "",
        "**Recommended fix:**",
        result["fix"],
        "",
        "**Verification:** Rerun the failed job after applying the "
        "approved fix and confirm the relevant step passes.",
    ])

    output = "\n".join(report)

    print(output)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(output + "\n")

    print("\nRule-based analysis completed successfully.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        sys.exit(1)
