import re

def parse_requirements(file_path):
    deps = []
    with open(file_path) as f:
        lines = f.read().replace("\\\n", " ").splitlines()  # Join multiline backslash lines

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Remove everything after semicolon (env markers) and --hash
        line = re.split(r"\s*(--hash=|;)", line)[0].strip()

        # Only support pinned dependencies
        match = re.match(r"^([a-zA-Z0-9_\-]+)==([^\s\\]+)", line)
        if match:
            package = match.group(1)
            version = match.group(2)
            deps.append({"package": package, "version": version})

    return deps
