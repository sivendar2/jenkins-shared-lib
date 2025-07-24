import os
import shutil
import stat
import subprocess
import sys

def run_command(cmd, cwd=None, capture_output=False):
    print(f"[RUN] {' '.join(cmd)}", flush=True)
    
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=capture_output,
        text=True,
        encoding="utf-8",
        errors="replace"  # prevent crash on non-UTF characters
    )

    if result.returncode != 0:
        err_msg = result.stderr.strip() if result.stderr else "Unknown error"
        print(f"❌ Command failed: {err_msg}", flush=True)
        sys.exit(1)

    return result.stdout.strip() if capture_output else None

def remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def clone_repo(repo_url, branch_name, local_dir="repo"):
    if os.path.exists(local_dir):
        shutil.rmtree(local_dir, onerror=remove_readonly)

    run_command(["git", "clone", "--quiet", repo_url, local_dir])

    existing_branches = run_command(
        ["git", "branch", "--list", branch_name],
        cwd=local_dir,
        capture_output=True
    )

    if existing_branches:
        run_command(["git", "checkout", "-q", branch_name], cwd=local_dir)
    else:
        run_command(["git", "checkout", "-b", branch_name, "-q"], cwd=local_dir)

    return local_dir

def create_commit_and_pr(repo_path, branch_name):
    run_command(["git", "add", "."], cwd=repo_path)

    status = run_command(
        ["git", "status", "--porcelain"],
        cwd=repo_path,
        capture_output=True
    )

    if not status:
        print("⚠️ No changes to commit.", flush=True)
        return None

    run_command(["git", "commit", "-m", "fix: auto-remediated vulnerabilities"], cwd=repo_path)
    run_command(["git", "push", "-u", "origin", branch_name], cwd=repo_path)

    return run_command([
        "gh", "pr", "create",
        "--title", "Security Fix: Auto Remediation",
        "--body", "This PR fixes CVEs and SAST findings.",
        "--base", "main",
        "--head", branch_name
    ], cwd=repo_path, capture_output=True)
