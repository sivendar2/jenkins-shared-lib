import csv
import json
import os
import xml.etree.ElementTree as ET

import requests
def read_cve_database1(csv_file):
    print(f"📖 Reading CVEs from {csv_file}...")
    cves = []
    with open(csv_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cves.append(row)
    return cves
def read_cve_database(file_path):
    cve_list = []

    # ✅ Ensure output directory exists
    os.makedirs("output", exist_ok=True)

    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_list.append(row)

    # ✅ Save mapping as both JSON and CSV
    with open('output/cve_cwe_mapping.json', 'w') as f:
        json.dump(cve_list, f, indent=2)

    with open('output/cve_cwe_mapping.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "component", "remediation", "cwe_id"])
        writer.writeheader()
        writer.writerows(cve_list)

    return cve_list

def match_cves_to_repo(cves, repo_path):
    print("Matching CVEs to repo...")
    # For now, assume all CVEs match
    return cves


def fetch_cve_data_from_osv(component):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": component,
            "ecosystem": "Maven"
        }
    }
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Failed to fetch data from OSV for {component}: {e}")
def load_cwe_to_rule_map(csv_file):
    mapping = {}
    with open(csv_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cwe = row["CWE"].strip()
            rule = row["SemgrepRule"].strip()
            mapping[cwe] = rule
    return mapping


def map_cwe_to_semgrep_template(cwe_id):
    """Return a basic Semgrep rule template snippet for given CWE."""
    cwe_rules = {
        "CWE-95": {
            "id": "cwe-95-code-injection",
            "message": "Potential code injection detected.",
            "patterns": [
                {"pattern-either": [{"pattern": "eval($X)"}, {"pattern": "exec($X)"}]}
            ],
            "languages": ["javascript", "python"],
            "severity": "ERROR",
            "fix": None  # You can add autofix pattern here if applicable
        },
        "CWE-89": {
            "id": "cwe-89-sql-injection",
            "message": "Possible SQL injection via string concatenation.",
            "patterns": [
                {"pattern": "$QUERY + $UNTRUSTED_INPUT"}
            ],
            "languages": ["java", "python"],
            "severity": "ERROR",
            "fix": None
        }
        # Add more CWE mappings as needed
    }
    return cwe_rules.get(cwe_id)

def generate_semgrep_rule_yaml(cve_data):
    """Generate a Semgrep YAML rule from CVE info and CWE mapping."""
    cwe_id = None
    if "cve" in cve_data:
        # Extract CWE ID from CVE (this depends on your CVE format)
        cwe_id = cve_data["cve"].get("cwe")
    elif "vulns" in cve_data:
        # OSV format
        cwe_id = cve_data["vulns"][0].get("cwe", None) if cve_data["vulns"] else None

    if not cwe_id:
        print("⚠️ No CWE found; skipping rule generation")
        return None

   # template = map_cwe_to_semgrep_template(cwe_id)
    #if not template:
     #   print(f"⚠️ No Semgrep template found for CWE {cwe_id}")
      #  return None

    # Fill in additional info from CVE data if needed
   # yaml_rule = {
    #    "rules": [
     #       {
      #          "id": template["id"],
       ##        "severity": template["severity"],
         #       "languages": template["languages"],
          ## }
        #]
    #}
    #if template.get("fix"):
     #   yaml_rule["rules"][0]["fix"] = template["fix"]

    #return yaml.dump(yaml_rule, sort_keys=False)
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
