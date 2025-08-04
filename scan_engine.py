import os
from mysecscan.scanners.osv_scanner import query_osv

def scan_file(file_path, ecosystem):
    if ecosystem == "PyPI":
        from mysecscan.parsers.python_parser import parse_requirements
        deps = parse_requirements(file_path)
    elif ecosystem == "npm":
        from mysecscan.parsers.node_parser import parse_package_json
        deps = parse_package_json(file_path)
    elif ecosystem == "Go":
        from mysecscan.parsers.go_parser import parse_go_mod
        deps = parse_go_mod(file_path)
    elif ecosystem == "crates.io":
        from mysecscan.parsers.rust_parser import parse_cargo_lock
        deps = parse_cargo_lock(file_path)
    elif ecosystem == "Maven":
        from mysecscan.parsers.java_parser import parse_pom
        deps = parse_pom(file_path)
    else:
        print(f"⚠️ Unsupported ecosystem: {ecosystem}")
        return []

    results = []
    for dep in deps:
        vulns = query_osv(
            dep["package"],
            dep["version"],
            ecosystem=dep.get("ecosystem", ecosystem)
        )
        if vulns:
            results.append({**dep, "ecosystem": ecosystem, "vulns": vulns})
    return results
