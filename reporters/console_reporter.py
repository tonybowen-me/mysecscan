import re
from collections import defaultdict
from packaging.version import parse as parse_version, InvalidVersion
from cvss import CVSS3


def is_valid_version(v):
    """Filter out git hashes or invalid versions"""
    if not v or len(v) > 30 or not re.match(r"^\d+(\.\d+)*", v):
        return False
    try:
        parse_version(v)
        return True
    except InvalidVersion:
        return False


def print_vulnerabilities(dependencies_with_vulns):
    print("\nSummary Report:\n")
    fixes_by_package = defaultdict(list)
    severity_by_package = defaultdict(list)

    for dep in dependencies_with_vulns:
        package = dep["package"]
        version = dep["version"]
        vulns = dep["vulns"]

        for vuln in vulns:
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fix = event["fixed"]
                            if is_valid_version(fix):
                                fixes_by_package[(package, version)].append(fix)

            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    vector = sev.get("score")
                    try:
                        cvss = CVSS3(vector)
                        score = cvss.scores()[0]  # Base score
                        severity_by_package[(package, version)].append(score)
                    except Exception:
                        continue

    for (package, version), fix_versions in fixes_by_package.items():
        scores = severity_by_package.get((package, version), [])
        if scores:
            max_sev = max(scores)
            sev_label = (
                "🟢 Low" if max_sev < 4 else
                "🟠 Medium" if max_sev < 7 else
                "🔴 High" if max_sev < 9 else
                "🔥 Critical"
            )
            sev_str = f"{sev_label}, CVSS {max_sev}"
        else:
            sev_str = "❓ Unknown severity"

        if fix_versions:
            highest_fix = max(fix_versions, key=parse_version)
            print(f"{package}=={version} → ❌ vulnerable — upgrade to: {highest_fix}  (Severity: {sev_str})")
        else:
            print(f"{package}=={version} → ❌ vulnerable — no known semantic fix  (Severity: {sev_str})")
