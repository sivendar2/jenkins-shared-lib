import sys
import os
import subprocess
import argparse
import json

# Add current directory to path for utils
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from git_utils import clone_repo, create_commit_and_pr
from semgrep_utils import run_semgrep, suggest_fixes, apply_auto_fix
from cve_utils import read_cve_database, match_cves_to_repo, apply_dependency_fix
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
        print("Java Fixer Output:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print("Java Fixer Error:\n", e.stderr)

def main(args):
    repo_path = clone_repo(args.repo_url, args.branch_name)

    # Step 1: Patch vulnerable dependencies
    cves = read_cve_database(args.cve_file)
    matched = match_cves_to_repo(cves, repo_path)
    pom_path = os.path.join(repo_path, "pom.xml")
    for cve in matched:
        apply_dependency_fix(cve, pom_path)

    # Step 2: Run Semgrep
    findings = run_semgrep(args.semgrep_rules, repo_path)
    suggestions = suggest_fixes(findings)

    # Step 3: Apply Fixes
    for suggestion in suggestions:
        rel_path = suggestion["file"].replace("repo/", "").replace("repo\\", "")
        abs_path = os.path.join(repo_path, rel_path)

        # Dispatch to Java fixer or semgrep fix
        if "Statement" in suggestion["message"] or "JdbcTemplate" in suggestion["message"]:
            run_java_fixer(abs_path)
        else:
            apply_auto_fix(abs_path)

    # Step 4: Test + Commit + PR
    run_tests()
    pr_url = create_commit_and_pr(repo_path, args.branch_name)
    if pr_url:
        notify_slack(args.slack_webhook, pr_url)
        update_dashboard()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated DevSecOps Remediation Tool")
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--branch-name", default="fix/security-issue")
    parser.add_argument("--cve-file", default="cves.csv")
    parser.add_argument("--semgrep-rules", default="sqli.yml")
    parser.add_argument("--slack-webhook", default="")
    args = parser.parse_args()
    main(args)
