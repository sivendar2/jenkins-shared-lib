import os
import subprocess
import json
import shutil
import sys
import requests
import stat
import csv
import xml.etree.ElementTree as ET
from datetime import datetime

REPO_URL = "https://github.com/sivendar2/employee-department-1.git"
LOCAL_REPO = "repo"
BRANCH_NAME = f"fix/sql-injection-{datetime.today().strftime('%Y%m%d-%H%M%S')}"
SEMGRREP_RULES = "sqli.yml"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX"

def run_command(cmd, cwd=None, capture_output=False):
    print(f"🟢 Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=capture_output, text=True)
    if result.returncode != 0:
        print(f"❌ Command failed: {result.stderr}")
        sys.exit(1)
    return result.stdout.strip() if capture_output else None

def remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def clone_repo():
    if os.path.exists(LOCAL_REPO):
        print("🧹 Cleaning up old repo...")
        shutil.rmtree(LOCAL_REPO, onerror=remove_readonly)
    run_command(["git", "clone", REPO_URL, LOCAL_REPO])
    run_command(["git", "checkout", "-b", BRANCH_NAME], cwd=LOCAL_REPO)

def run_semgrep():
    output_file = "semgrep-report.json"
    run_command([
        "semgrep", "--config", SEMGRREP_RULES,
        "--json", "--output", output_file, LOCAL_REPO
    ])
    with open(output_file) as f:
        return json.load(f)

def read_cve_database(cve_file="cves.csv"):
    cves = []
    with open(cve_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cves.append(row)
    return cves

def match_cves_to_repo(cves, repo_path):
    matched = []
    pom_file = os.path.join(repo_path, "pom.xml")
    if not os.path.exists(pom_file):
        print("⚠️ pom.xml not found!")
        return matched
    with open(pom_file) as f:
        content = f.read()
    for cve in cves:
        if cve["component"] in content and cve["version"] in content:
            matched.append(cve)
    return matched

def apply_dependency_fix(cve, pom_file):
    tree = ET.parse(pom_file)
    root = tree.getroot()
    namespace = {'ns': 'http://maven.apache.org/POM/4.0.0'}
    ET.register_namespace('', namespace['ns'])  # Prevents ns0 prefixes

    fixed = False

    for dep in root.findall(".//ns:dependency", namespace):
        group = dep.find("ns:groupId", namespace)
        artifact = dep.find("ns:artifactId", namespace)
        version = dep.find("ns:version", namespace)

        group_val = group.text.strip() if group is not None and group.text else ""
        artifact_val = artifact.text.strip() if artifact is not None and artifact.text else ""
        version_val = version.text.strip() if version is not None and version.text else ""

        # DEBUG
        print(f"🔍 Checking dependency: {group_val}:{artifact_val}:{version_val}")

        if artifact_val == cve["component"] and version_val == cve["version"]:
         print(f"✅ Match found → Updating {artifact_val}:{version_val} → {cve['remediation']}")
         version.text = cve["remediation"].replace("Upgrade to ", "").strip()
         fixed = True

    if fixed:
        tree.write(pom_file, encoding="utf-8", xml_declaration=True)
        print("💾 pom.xml updated.")
    else:
        print(f"⚠️ No match found in pom.xml for {cve['component']}:{cve['version']}")

def suggest_fixes(findings):
    fixes = []
    for f in findings["results"]:
        file_path = f["path"]
        if "Statement" in f["extra"]["lines"]:
            suggestion = f"""
⚠️ SQL Injection risk found:
File: {file_path}
Line: {f['start']['line']}
Replace `Statement` with `PreparedStatement`
"""
            fixes.append((file_path, suggestion))
    return fixes

def apply_auto_fix(file_path, finding):
    print(f"🛠️ Applying fix to: {file_path}")
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    changed = False
    for i in range(len(lines)):
        if "Statement" in lines[i] and "createStatement" in lines[i]:
            lines[i] = lines[i].replace("Statement", "PreparedStatement").replace("createStatement", "prepareStatement")
            changed = True
        elif "jdbcTemplate.query" in lines[i] and "+" in lines[i]:
            # Example fix for JDBC template string concat
            lines[i] = '        return jdbcTemplate.query("SELECT * FROM employees WHERE department_id = ?", new BeanPropertyRowMapper<>(Employee.class), departmentName);\n'
            changed = True

    if changed:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f"✅ Applied fix in: {file_path}")
    else:
        print(f"⚠️ No fix applied to: {file_path}")

def run_tests():
    print("✅ [Mock] Tests passed")

def create_commit_and_pr():
    run_command(["git", "add", "."], cwd=LOCAL_REPO)

    # Check for staged changes before committing
    status_output = run_command(["git", "status", "--porcelain"], cwd=LOCAL_REPO, capture_output=True)
    if not status_output:
        print("⚠️ No changes detected, skipping commit and PR creation.")
        return None

    run_command(["git", "commit", "-m", "fix: patched SQL injection and dependency vulnerabilities"], cwd=LOCAL_REPO)

    # Optional: Only do this if you expect the branch may already exist
    # run_command(["git", "pull", "--rebase", "origin", BRANCH_NAME], cwd=LOCAL_REPO)

    run_command(["git", "push", "--force-with-lease", "-u", "origin", BRANCH_NAME], cwd=LOCAL_REPO)

    pr_output = run_command([
        "gh", "pr", "create",
        "--title", "Security Fix: SQL Injection & CVE Remediation",
        "--body", "This PR auto-remediates SQL injection risks and known vulnerable dependencies from CVE database.",
        "--base", "main",
        "--head", BRANCH_NAME
    ], cwd=LOCAL_REPO, capture_output=True)

    return pr_output

def notify_slack(pr_url):
    payload = {
        "text": f"✅ Security PR Created: {pr_url}"
    }
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if response.status_code == 200:
            print("🔔 Slack notified")
        else:
            print(f"⚠️ Slack notification failed: {response.text}")
    except Exception as e:
        print(f"⚠️ Slack notification error: {e}")

def update_dashboard(status="fixed"):
    print(f"📊 [Mock] Dashboard updated with status: {status}")

def main():
    print("🚀 Starting vulnerability remediation workflow...")
    clone_repo()

    # Step 1: Read and apply CVE patches to pom.xml
    cves = read_cve_database("cves.csv")
    matched_cves = match_cves_to_repo(cves, LOCAL_REPO)
    pom_path = os.path.join(LOCAL_REPO, "pom.xml")
    print(f"📦 Found {len(matched_cves)} dependency issues")
    for cve in matched_cves:
        print(f"🧩 Matched CVE: {cve}")
        apply_dependency_fix(cve, pom_path)

    with open(pom_path, 'r') as f:
        pom_content = f.read()
    if any(cve['remediation'] in pom_content for cve in matched_cves):
        print("📝 pom.xml successfully updated with new versions.")
    else:
        print("⚠️ No changes were made to pom.xml — check if remediation versions already present or match logic failed.")

    # Step 2: Run Semgrep and patch source code
    findings = run_semgrep()
    print(f"🔍 Found {len(findings['results'])} Semgrep issue(s)")
    suggestions = suggest_fixes(findings)
    for suggestion in suggestions:
      print(suggestion["message"])
      full_path = os.path.join(LOCAL_REPO, suggestion["file"])
      apply_auto_fix(full_path, suggestion)

    # Step 3: Test, Commit, PR, Notify
    run_tests()
    pr_output = create_commit_and_pr()
    if pr_output:
        pr_url = f"https://github.com/sivendar2/employee-department-1/pull/new/{BRANCH_NAME}"
        notify_slack(pr_url)
        update_dashboard()
    else:
        print("📭 No PR created as no changes were made.")

    print("✅ Workflow completed.")


if __name__ == "__main__":
    main()
