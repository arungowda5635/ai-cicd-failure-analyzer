
def analyze(log):
    import re

    lines = log.splitlines()
    findings = []
    seen_findings = set()

    # Collect every matching rule, rather than returning after the first match.
    for category, patterns, cause, fix in RULES:
        matching_lines = []

        for line in lines:
            if any(pattern.lower() in line.lower() for pattern in patterns):
                clean_line = line.strip()

                if clean_line and clean_line not in matching_lines:
                    matching_lines.append(clean_line)

        if matching_lines and category not in seen_findings:
            seen_findings.add(category)
            findings.append({
                "category": category,
                "cause": cause,
                "fix": fix,
                "evidence": matching_lines[-10:],
            })

    # Also capture common errors that may not match any existing rule.
    generic_error_patterns = [
        r"\bSyntaxError\b",
        r"\bTypeError\b",
        r"\bReferenceError\b",
        r"\bRangeError\b",
        r"\bModuleNotFoundError\b",
        r"\bImportError\b",
        r"\bError:\b",
        r"\bERR_[A-Z0-9_]+\b",
        r"\bE[A-Z0-9]{3,}\b",
        r"\bFATAL\b",
        r"\bFAILED\b",
        r"\bFAILURE\b",
        r"\bException\b",
        r"\bTraceback \(most recent call last\)",
    ]

    unclassified = []
    seen_lines = set()

    for line in lines:
        clean_line = line.strip()

        if not clean_line or clean_line in seen_lines:
            continue

        seen_lines.add(clean_line)

        if any(
            re.search(pattern, clean_line, re.IGNORECASE)
            for pattern in generic_error_patterns
        ):
            # Avoid repeating evidence already reported under a known category.
            already_reported = any(
                clean_line in finding["evidence"]
                for finding in findings
            )

            if not already_reported:
                unclassified.append(clean_line)

    report = [
        "# CI/CD Failure Analysis",
        "",
        "**Analysis mode:** Rule-based (no API required)",
        "",
        f"**Detected error categories:** {len(findings)}",
        "",
    ]

    if findings:
        for index, finding in enumerate(findings, start=1):
            report.extend([
                f"## {index}. {finding['category']}",
                "",
                f"**Likely cause:** {finding['cause']}",
                "",
                "**Evidence from the log:**",
                "",
            ])

            for evidence in finding["evidence"]:
                report.append(f"- `{evidence[:500]}`")

            report.extend([
                "",
                f"**Recommended fix:** {finding['fix']}",
                "",
            ])
    else:
        report.extend([
            "No known error categories matched the downloaded log.",
            "",
        ])

    report.extend([
        "## Other / Unclassified Errors",
        "",
    ])

    if unclassified:
        for line in unclassified[:50]:
            report.append(f"- `{line[:500]}`")

        if len(unclassified) > 50:
            report.append(
                f"- Plus {len(unclassified) - 50} additional error-like lines."
            )
    else:
        report.append(
            "No additional unclassified error patterns were detected."
        )

    report.extend([
        "",
        "## Verification",
        "",
        "Review each finding against the original failed step. "
        "Some messages may be secondary errors caused by an earlier failure. "
        "Fix the underlying cause and rerun the failed workflow.",
    ])

    return "\n".join(report) + "\n"

import os
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
            summary.write(report + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Analyzer failed: {exc}", file=sys.stderr)
        sys.exit(1)
