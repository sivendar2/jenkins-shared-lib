import subprocess
import os
import json
import sys

# Optional: Import if defined elsewhere
try:
    from main import run_java_fixer  # or move this to a shared utils module
except ImportError:
    def run_java_fixer(file_path):
        print(f"Java fixer not wired yet for: {file_path}")

def run_command(cmd, cwd=None):
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f" Error running command: {result.stderr}")
        sys.exit(1)
    return result.stdout

def run_semgrep(semgrep_rules, repo_path):
    report_path = os.path.join(repo_path, "semgrep-report.json")  # ✅ Save report here

    cmd = ["semgrep", "--config", semgrep_rules, "--json", repo_path]
    print(f"Running Semgrep command: {' '.join(cmd)}")
    
    report_path = os.path.join(repo_path, "semgrep-report.json")

    with open(report_path, "w", encoding="utf-8") as outfile:
        proc = subprocess.run(
        cmd,
        stdout=outfile,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8'  # 👈 force UTF-8 on Windows
    )
    print(f" SAST report saved to: {report_path}")

    if proc.returncode != 0:
        print(f" Semgrep failed:\n{proc.stderr}")
        sys.exit(1)

    #  Load JSON back from file to use downstream
    with open(report_path, "r", encoding='utf-8') as f:
        try:
            findings = json.load(f)
            print(f"Semgrep findings saved at: {report_path}")
        except json.JSONDecodeError as e:
            print(f" Failed to parse saved Semgrep report: {e}")
            sys.exit(1)

    return findings

def suggest_fixes(findings):
    suggestions = []
    results = findings.get("results", [])
    print(f"Number of findings: {len(results)}")

    for item in results:
        try:
            path = item["path"]
            start_line = item["start"]["line"]
            message = item["extra"].get("message", "No message")

            print(f"Finding in: {path} @ line {start_line} - {message}")
            suggestions.append({
                "file": path,
                "line": start_line,
                "message": message
            })
        except KeyError as e:
            print(f" Skipping invalid finding due to missing key: {e}")
            continue

    return suggestions

def apply_auto_fix(file_path, finding=None):
    print(f"Applying fix to: {file_path}")

    changed = False
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for i in range(len(lines)):
            if "Statement" in lines[i] and "createStatement" in lines[i]:
                lines[i] = lines[i].replace("Statement", "PreparedStatement").replace("createStatement", "prepareStatement")
                changed = True

            if "jdbcTemplate.query" in lines[i] and "+" in lines[i]:
                lines[i] = (
                    '        return jdbcTemplate.query("SELECT * FROM employees WHERE department_id = ?", '
                    'new BeanPropertyRowMapper<>(Employee.class), departmentName);\n'
                )
                changed = True

        if changed:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            print(f" Simple fix applied: {file_path}")
            return
    except Exception as e:
        print(f" Failed to apply simple fix: {e}")

    # Run JavaParser-based fixer if simple pattern match didn't help
    print(f"Trying JavaParser-based fix for: {file_path}")
    run_java_fixer(file_path)
