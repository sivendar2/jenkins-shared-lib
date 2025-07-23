import sys
import os
import subprocess
import argparse
import json
import requests
import io
import traceback

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

# Ensure stdout/stderr encoding is UTF-8 for Windows terminals
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


def run_java_fixer(file_path):
    jar_path = os.path.join(os.path.dirname(__file__), "java-fixer.jar")
    if not os.path.exists(jar_path):
        print(f"❌ java-fixer.jar not found at {jar_path}")
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
        print("✅ Java Fixer Output:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print("❌ Java Fixer Error:\n", e.stderr)


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
            print(f"📝 Generated Semgrep rule for {cve_id} at {rule_file}")

            cmd = [
                "semgrep",
                "--config", rule_file,
                "--autofix",
                repo_path
            ]
            try:
                subprocess.run(cmd, check=True)
                print(f"✅ Ran Semgrep autofix for rule {cve_id}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Semgrep failed for {cve_id}: {e}")


def main(args):
    print("🔄 Step 1: Cloning repo...")
    repo_path = clone_repo(args.repo_url, args.branch_name)
    print(f"✅ Repo cloned to: {repo_path}")

    print("🔍 Step 2: Running Snyk scan...")
    snyk_report = run_snyk_scan(repo_path)
    print(f"✅ Snyk report: {snyk_report}")

    print("🔧 Step 3: Syncing Snyk fixes...")
    pom_path = os.path.join(repo_path, "pom.xml")
    print(f"Looking for pom.xml at: {pom_path}")
    sync_snyk_fixes(report_path=snyk_report, pom_file_path=pom_path)

    print("📖 Step 4: Reading CVEs...")
    cves = read_cve_database(args.cve_file)
    print(f"✅ Loaded {len(cves)} CVEs")

    print("📌 Step 5: Matching CVEs to repo...")
    matched = match_cves_to_repo(cves, repo_path)
    print(f"✅ Matched {len(matched)} CVEs")

    print("🧪 Step 6: Applying dependency fixes...")
    for cve in matched:
        print(f"Applying fix for {cve['cve_id']}")
        apply_dependency_fix(cve, pom_path)

    print("⚙️ Step 7: Generating semgrep rules...")
    generate_and_apply_semgrep_rules(matched, repo_path)

    print("🔍 Step 8: Running static semgrep...")
    findings = run_semgrep(args.semgrep_rules, repo_path)
    print(f"✅ Found {len(findings)} semgrep issues")

    print("🛠 Step 9: Suggesting fixes...")
    suggestions = suggest_fixes(findings)

    print("🩹 Step 10: Applying autofixes...")
    for item in suggestions:
        relative_path = os.path.relpath(item["file"], start="repo").replace("\\", "/")
        file_path = os.path.join(repo_path, relative_path)
        if file_path.endswith(".java"):
            print(f" Fixing (JavaParser): {item['file']}")
            run_java_fixer(file_path)
        else:
            print(f" Fixing (Semgrep): {item['file']}")
            apply_auto_fix(file_path, item)

    print("🚀 Step 11: Creating PR...")
    pr_url = create_commit_and_pr(repo_path, args.branch_name)

    if pr_url:
        print(f"✅ Pull Request Created: {pr_url}")
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

    os.makedirs("scripts/output", exist_ok=True)
    log_path = "scripts/output/main_log.txt"

    with open(log_path, "w", encoding="utf-8") as log:
        log.write("Starting run...\n")
        try:
            main(args)
            log.write("Completed main successfully.\n")
        except Exception as e:
            log.write(f"❌ Error: {str(e)}\n")
            log.write(traceback.format_exc())
            print("❌ Exception occurred. Check log file for details:", log_path)
