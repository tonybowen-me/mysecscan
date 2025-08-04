import os
from mysecscan.parsers.python_parser import parse_requirements
from mysecscan.parsers.node_parser import parse_package_json
from mysecscan.scanners.osv_scanner import query_osv
from mysecscan.reporters.console_reporter import print_vulnerabilities

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
    return results  # ✅ Make sure this always returns a list


def main():
    all_results = []
    if os.path.exists("requirements.txt"):
        print("[*] Scanning Python (requirements.txt)...")
        all_results += scan_file("requirements.txt", "PyPI")
    if os.path.exists("package.json"):
        print("[*] Scanning JavaScript (npm)...")
        all_results += scan_file("package.json", "npm")

    if os.path.exists("go.mod"):
        print("[*] Scanning Go...")
        all_results += scan_file("go.mod", "Go")

    if os.path.exists("Cargo.lock"):
        print("[*] Scanning Rust...")
        all_results += scan_file("Cargo.lock", "crates.io")

    if os.path.exists("pom.xml"):
        print("[*] Scanning Java (Maven)...")
        all_results += scan_file("pom.xml", "Maven")

    if all_results:
        print_vulnerabilities(all_results)
    else:
        print("🎉 No known vulnerabilities found (or no supported files detected).")

if __name__ == "__main__":
    main()
