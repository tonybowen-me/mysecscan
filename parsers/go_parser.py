def parse_go_mod(file_path):
    deps = []
    with open(file_path) as f:
        for line in f:
            if line.startswith("require"):
                parts = line.split()
                if len(parts) >= 3:
                    pkg = parts[1]
                    ver = parts[2].strip()
                    deps.append({"package": pkg, "version": ver, "ecosystem": "Go"})
    return deps
