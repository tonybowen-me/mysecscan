import toml

def parse_cargo_lock(file_path):
    data = toml.load(file_path)
    deps = []
    for pkg in data.get("package", []):
        deps.append({
            "package": pkg["name"],
            "version": pkg["version"],
            "ecosystem": "crates.io"
        })
    return deps
