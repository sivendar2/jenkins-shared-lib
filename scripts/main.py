import sys
import os
import subprocess
import argparse
import json
import requests

# Add current directory to path for utils
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from git_utils import clone_repo, create_commit_and_pr
from semgrep_utils import run_semgrep, suggest_fixes, apply_auto_fix
from snyk_utils import run_snyk_scan, sync_snyk_fixes
from cve_utils import (
    fetch_cve_data_from_osv,
    generate_semgrep_rule_yaml,
    read_cve_database,
    match_cves_to_repo,
    apply_dependency_fix
)
from notify_utils import notify_slack, update_dashboard
from test_utils import run_tests

def run_java_fixer(file_path):
    jar_path = os.path.join(os.path.dirname(__file__), "java-fixer.jar")
    if not os.path.exists(jar_path):
        print(f" java-fixer.jar not found at {jar_path}")
        return

    print(f"🛠 Running Java fixer on: {file_path}")
    try:
        result = subprocess.run(
            ["java", "-jar", jar_path, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        print(" Java Fixer Output:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print(" Java Fixer Error:\n", e.stderr)

def generate_and_apply_semgrep_rules(cves, repo_path):
    semgrep_rules_dir = os.path.join(repo_path, "generated_semgrep_rules")
    os.makedirs(semgrep_rules_dir, exist_ok=True)

    for cve in cves:
        cve_id = cve.get("cve_id", "unknown")
        component = cve.get("component", "")
        cve_data = fetch_cve_data_from_osv(component)
        if not cve_data:
            continue

        rule_yaml = generate_semgrep_rule_yaml(cve_data)
        if rule_yaml:
            rule_file = os.path.join(semgrep_rules_dir, f"{cve_id}.yml")
            with open(rule_file, "w") as f:
                f.write(rule_yaml)
            print(f" Generated Semgrep rule for {cve_id} at {rule_file}")

            cmd = [
                "semgrep",
                "--config", rule_file,
                "--autofix",
                repo_path
            ]
            try:
                subprocess.run(cmd, check=True)
                print(f" Ran Semgrep autofix for rule {cve_id}")
            except subprocess.CalledProcessError as e:
                print(f" Semgrep failed for {cve_id}: {e}")
def main(args):
 # Step 1: Clone repo + checkout new branch
    repo_path = clone_repo(args.repo_url, args.branch_name)

    # Step 2: Run Snyk Scan (before Semgrep or dependency fixing)
    snyk_report = run_snyk_scan(repo_path)

    # Step 3: Apply Snyk Fixes to pom.xml
    sync_snyk_fixes(
        report_path=snyk_report,
        pom_file_path=os.path.join(repo_path, "pom.xml")
    )

    # Step 4: Read and match CVEs
    cves = read_cve_database(args.cve_file)
    matched = match_cves_to_repo(cves, repo_path)

    # Step 5: Patch dependencies manually from CVE list
    pom_path = os.path.join(repo_path, "pom.xml")
    for cve in matched:
        apply_dependency_fix(cve, pom_path)

    # Step 6: Generate Semgrep rules from CVEs
    generate_and_apply_semgrep_rules(matched, repo_path)

    # Step 7: Run static rules (Semgrep)
    findings = run_semgrep(args.semgrep_rules, repo_path)
    suggestions = suggest_fixes(findings)

    # Step 8: Apply fixes
    for item in suggestions:
        relative_path = os.path.relpath(item["file"], start="repo").replace("\\", "/")
        file_path = os.path.join(repo_path, relative_path)
        if file_path.endswith(".java"):
            print(f" Fixing file: {item['file']} → {file_path}")
            run_java_fixer(file_path)
        else:
            apply_auto_fix(file_path, item)

    # Step 9: Test
    run_tests()  # You may want to pass cwd=repo_path

    # Step 10: PR creation
    pr_url = create_commit_and_pr(repo_path, args.branch_name)

    # Step 11: Notify
    if pr_url:
        notify_slack(args.slack_webhook, pr_url)
        update_dashboard()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated DevSecOps Remediation Tool")
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--branch-name", default="fix/security-issue")
    parser.add_argument("--cve-file", default="cves.csv")
    parser.add_argument("--semgrep-rules", default="rules/java-security/")
    parser.add_argument("--slack-webhook", default="")
    args = parser.parse_args()
    main(args)
