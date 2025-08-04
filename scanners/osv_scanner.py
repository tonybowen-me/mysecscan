import requests

def query_osv(package_name, version, ecosystem="PyPI"):
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    response = requests.post("https://api.osv.dev/v1/query", json=payload)
    if response.status_code == 200:
        return response.json().get("vulns", [])
    return []
