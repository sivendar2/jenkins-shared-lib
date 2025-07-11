import subprocess, sys

print("[INFO] Running Semgrep with autofix...")
res = subprocess.run([
    "semgrep", "scan", "--config", ".semgrep/sql-injection-autofix.yml",
    "--autofix", "--json"
], stdout=open("semgrep-report.json", "w"))

print(f"[INFO] Semgrep finished with exit code {res.returncode}")
sys.exit(res.returncode)
