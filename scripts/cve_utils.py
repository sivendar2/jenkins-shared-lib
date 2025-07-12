import csv
import os
import xml.etree.ElementTree as ET
def read_cve_database(csv_file):
    print(f"📖 Reading CVEs from {csv_file}...")
    cves = []
    with open(csv_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cves.append(row)
    return cves

def match_cves_to_repo(cves, repo_path):
    print("Matching CVEs to repo...")
    # For now, assume all CVEs match
    return cves

import os
import xml.etree.ElementTree as ET

def apply_dependency_fix(cve, pom_file_path):
    print(f"🛠️ Patching {pom_file_path} for {cve.get('cve_id')}...")

    if not os.path.exists(pom_file_path):
        print(f" pom.xml not found at {pom_file_path}")
        return

    tree = ET.parse(pom_file_path)
    root = tree.getroot()

    # Namespace handling (Maven POMs use XML namespaces)
    ns = {'ns': 'http://maven.apache.org/POM/4.0.0'}
    ET.register_namespace('', ns['ns'])

    dependencies = root.find('ns:dependencies', ns)
    if dependencies is None:
        print(" No <dependencies> section found in pom.xml")
        return

    matched = False
    for dep in dependencies.findall('ns:dependency', ns):
        group_id = dep.find('ns:groupId', ns)
        artifact_id = dep.find('ns:artifactId', ns)
        version = dep.find('ns:version', ns)

        if group_id is None or artifact_id is None:
            continue

        group = group_id.text.strip()
        artifact = artifact_id.text.strip()

        # Check if this matches the CVE component
        if artifact == cve['component']:
            if version is not None:
                old_version = version.text
                version.text = cve['remediation'].replace("Upgrade to", "").strip()
                print(f" Updated {group}:{artifact} from version {old_version} → {version.text}")
                matched = True
            else:
                print(f" No version tag found for {group}:{artifact}")

    if matched:
        tree.write(pom_file_path, encoding="utf-8", xml_declaration=True)
    else:
        print(f" Component '{cve['component']}' not found in pom.xml")
