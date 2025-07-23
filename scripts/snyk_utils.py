import os
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime


def run_snyk_scan(repo_path):
    snyk_path = shutil.which("snyk")
    if not snyk_path:
        raise RuntimeError("Snyk is not found in PATH. Please install it via `npm install -g snyk` or ensure it's in PATH.")

    snyk_report_path = os.path.join(repo_path, "snyk-report.json")
    print(f"Running Snyk scan on: {repo_path}")

    try:
        with open(snyk_report_path, "w") as report_file:
            result = subprocess.run(
                [snyk_path, "test", "--file=pom.xml", "--json"],
                cwd=repo_path,
                stdout=report_file,
                stderr=subprocess.PIPE,
                text=True
            )

        if result.returncode != 0:
            print("Snyk completed with issues (non-zero exit). This usually means vulnerabilities were found.")
            if result.stderr:
                print("🔻 stderr:", result.stderr.strip())

        print(f"Snyk report saved to {snyk_report_path}")
    except Exception as e:
        print(f"Unexpected error during Snyk scan: {e}")
        raise

    return snyk_report_path


def sync_snyk_fixes(report_path, pom_file_path):
    print(f"Reading Snyk report from {report_path}...")

    if not os.path.exists(report_path) or not os.path.exists(pom_file_path):
        print(" Required files not found.")
        return

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            snyk_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f" Failed to parse Snyk JSON: {e}")
        return

    tree = ET.parse(pom_file_path)
    root = tree.getroot()

    # Extract Maven namespace
    namespace = root.tag.split('}')[0].strip('{') if '}' in root.tag else ''
    ns = {'ns': namespace} if namespace else {}
    ET.register_namespace('', ns['ns'])

    deps = root.find('ns:dependencies', ns)
    if deps is None:
        print("No <dependencies> section found in pom.xml")
        return

    updated = False
    log_dir = os.path.join(os.path.dirname(pom_file_path), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"snyk-fix-log-{datetime.today().strftime('%Y%m%d')}.txt")

    with open(log_path, "w") as log:
        for vuln in snyk_data.get("vulnerabilities", []):
            try:
                raw_pkg = vuln.get("packageName", "")
                pkg = raw_pkg.split("@")[0].strip() if raw_pkg else ""
                upgrade_path = vuln.get("upgradePath", [])
                fixed_version = upgrade_path[-1] if upgrade_path else None

                if not pkg or not fixed_version:
                    continue

                for dep in deps.findall('ns:dependency', ns):
                    artifact_id = dep.find('ns:artifactId', ns)
                    version = dep.find('ns:version', ns)
                    group_id = dep.find('ns:groupId', ns)

                    if artifact_id is None or version is None or group_id is None:
                        continue

                    artifact = artifact_id.text.strip()
                    group = group_id.text.strip()
                    gav = f"{group}:{artifact}"
                    maven_pkg_format = f"pkg:maven/{group}/{artifact}"

                #    print(f"🧪 Checking: Snyk={pkg} | GAV={gav} | MavenPkg={maven_pkg_format}")

                    if pkg in (artifact, gav, maven_pkg_format):
                        old_version = version.text
                        version.text = fixed_version
                        updated = True
                        print(f"✅ Updated {gav} from {old_version} → {fixed_version}")
                        log.write(f"Updated {gav} from {old_version} to {fixed_version} via Snyk\n")

            except Exception as e:
                print(f" Error while processing vulnerability entry: {vuln}")
                print(f"    {e}")
                continue

    if updated:
        tree.write(pom_file_path, encoding="utf-8", xml_declaration=True)
        print(f" pom.xml updated. Log saved to {log_path}")
    else:
        print(" No matching dependencies found for Snyk fixes.")
