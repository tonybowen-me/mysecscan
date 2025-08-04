import json

def parse_package_json(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    deps = []

    for section in ["dependencies", "devDependencies"]:
        section_data = data.get(section, {})
        for package, version in section_data.items():
            # Strip version ranges like "^", "~", ">", etc.
            clean_version = version.lstrip("^~><= ")
            deps.append({
                "package": package,
                "version": clean_version,
                "ecosystem": "npm"
            })

    return deps
