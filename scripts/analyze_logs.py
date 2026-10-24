
def analyze(log):
    lines = log.splitlines()
    lower = log.lower()

    # Detect missing or unknown package/module errors first.
    package_patterns = [
        (
            r"cannot find module\s+['\"]([^'\"]+)['\"]",
            "Missing Node.js Module",
        ),
        (
            r"cannot find package\s+['\"]([^'\"]+)['\"]",
            "Missing Node.js Package",
        ),
        (
            r"module_not_found.*?['\"]([^'\"]+)['\"]",
            "Missing Node.js Module",
        ),
        (
            r"npm error 404.*?['\"]([^'\"]+)['\"]",
            "Unknown or Unavailable npm Package",
        ),
        (
            r"npm err! 404.*?['\"]([^'\"]+)['\"]",
            "Unknown or Unavailable npm Package",
        ),
        (
            r"npm error 404.*?package ['\"]?(@?[\w./-]+)",
            "Unknown or Unavailable npm Package",
        ),
        (
            r"npm err! 404.*?package ['\"]?(@?[\w./-]+)",
            "Unknown or Unavailable npm Package",
        ),
    ]

    for pattern, category in package_patterns:
        match = re.search(pattern, log, re.IGNORECASE)

        if match:
            package_name = match.group(1).strip()
            evidence_lines = [
                line.strip()
                for line in lines
                if any(
                    word in line.lower()
                    for word in [
                        "cannot find module",
                        "cannot find package",
                        "module_not_found",
                        "npm error 404",
                        "npm err! 404",
                    ]
                )
            ]

            evidence = "\n".join(
                f"- `{line[:400]}`"
                for line in evidence_lines[-5:]
            )

            return (
                "## Failure Analysis\n\n"
                f"**Category:** {category}\n\n"
                f"**Package or module:** `{package_name}`\n\n"
                "**Likely cause:** The requested package or module "
                "could not be resolved. It may be missing, misspelled, "
                "unavailable in the configured registry, or imported "
                "using an incorrect path.\n\n"
                f"**Evidence:**\n{evidence}\n\n"
                "**Recommended fix:**\n"
                "- Verify the package name and version.\n"
                "- Check package.json and package-lock.json.\n"
                "- Confirm the package is available in the configured npm registry.\n"
                "- Check whether the import path and module type are correct.\n"
                "- Reinstall dependencies in a trusted environment and rerun tests.\n\n"
                "**Verification:** Run `npm ls <package-name>` and "
                "`npm test` after correcting the issue.\n"
            )

    # Handle dependency resolution errors separately.
    if (
        "eresolve" in lower
        or "unable to resolve dependency tree" in lower
    ):
        evidence_lines = [
            line.strip()
            for line in lines
            if "eresolve" in line.lower()
            or "peer dep" in line.lower()
            or "dependency tree" in line.lower()
        ]

        evidence = "\n".join(
            f"- `{line[:400]}`"
            for line in evidence_lines[-5:]
        )

        return (
            "## Failure Analysis\n\n"
            "**Category:** Dependency Version Conflict\n\n"
            "**Likely cause:** npm could not resolve a compatible "
            "combination of package versions.\n\n"
            f"**Evidence:**\n{evidence}\n\n"
            "**Recommended fix:** Review the conflicting packages and "
            "their peer dependency requirements. Select compatible "
            "versions and rerun the tests.\n"
        )

    # Fall back to the existing general rules.
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
                "**Note:** This is a pattern-based diagnosis. "
                "Verify it against the full failed step log.\n"
            )

    tail = "\n".join(lines[-12:])[-3000:]

    return (
        "## Failure Analysis\n\n"
        "**Category:** Unknown Failure\n\n"
        "**Likely cause:** No known error pattern was detected.\n\n"
        f"**Recent log lines:**\n```\n{tail}\n```\n\n"
        "Review the first meaningful error in the failed workflow step.\n"
    )
