import xml.etree.ElementTree as ET

def parse_pom(file_path):
    deps = []
    tree = ET.parse(file_path)
    root = tree.getroot()

    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    for dep in root.findall(".//m:dependency", ns):
        gid = dep.find("m:groupId", ns).text
        aid = dep.find("m:artifactId", ns).text
        ver = dep.find("m:version", ns).text
        deps.append({
            "package": f"{gid}:{aid}",
            "version": ver,
            "ecosystem": "Maven"
        })
    return deps
