import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import argparse
from git_utils import clone_repo, create_commit_and_pr
from semgrep_utils import run_semgrep, suggest_fixes, apply_auto_fix
from cve_utils import read_cve_database, match_cves_to_repo, apply_dependency_fix
from notify_utils import notify_slack, update_dashboard
from test_utils import run_tests
import os

def main(args):
    repo_path = clone_repo(args.repo_url, args.branch_name)

    # CVE Patch Phase
    cves = read_cve_database(args.cve_file)
    matched = match_cves_to_repo(cves, repo_path)
    pom_path = os.path.join(repo_path, "pom.xml")
    for cve in matched:
        apply_dependency_fix(cve, pom_path)

    # Semgrep Patch Phase
    findings = run_semgrep(args.semgrep_rules, repo_path)
    suggestions = suggest_fixes(findings)

    for suggestion in suggestions:
     file_path = suggestion["file"]
     apply_auto_fix(file_path)
    

    # CI Actions
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
