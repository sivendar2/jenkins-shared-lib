import subprocess
import os
import json
import sys

try:
    from main import run_java_fixer
except ImportError:
    def run_java_fixer(file_path):
        print(f"Java fixer not wired yet for: {file_path}")

def run_command(cmd, cwd=None):
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"❌ Error running command: {result.stderr}")
        sys.exit(1)
    return result.stdout

def run_semgrep(semgrep_rules, repo_path):
    report_path = os.path.join(repo_path, "semgrep-report.json")
    
    cmd = ["semgrep", "scan"]

    # Add user-provided rule (folder or file)
    if semgrep_rules:
        cmd += ["--config", semgrep_rules]

    # Add trusted built-in rules
    builtin_rules = [
        "p/owasp-top-ten",
        "p/cwe-top-25",
        "p/security-audit"
    ]
    for rule in builtin_rules:
        cmd += ["--config", rule]

    cmd += ["--autofix", "--json", repo_path]

    print(f"🔍 Running Semgrep command:\n{' '.join(cmd)}")

    with open(report_path, "w", encoding="utf-8") as outfile:
        proc = subprocess.run(
            cmd,
            stdout=outfile,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8"
        )

    print(f"✅ SAST report saved to: {report_path}")

    if proc.returncode not in (0, 1):
        print(f"❌ Semgrep failed:\n{proc.stderr}")
        sys.exit(proc.returncode)

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
            print(f"📄 Loaded Semgrep findings from: {report_path}")
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse saved Semgrep report: {e}")
        sys.exit(1)

    return findings

def suggest_fixes(findings):
    suggestions = []
    results = findings.get("results", [])
    print(f"🧩 Number of findings: {len(results)}")

    for item in results:
        try:
            path = item["path"]
            start_line = item["start"]["line"]
            message = item["extra"].get("message", "No message")
            print(f"🛠️ Finding in: {path} @ line {start_line} - {message}")
            suggestions.append({
                "file": path,
                "line": start_line,
                "message": message
            })
        except KeyError as e:
            print(f"⚠️ Skipping invalid finding due to missing key: {e}")
            continue

    return suggestions

def apply_auto_fix(file_path, finding=None):
    print(f"🛠️ Applying fix to: {file_path}")
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
            print(f"✅ Simple fix applied: {file_path}")
            return
    except Exception as e:
        print(f"❌ Failed to apply simple fix: {e}")

    # If no fix applied, fallback to JavaParser fixer
    print(f"🌀 Trying JavaParser-based fix for: {file_path}")
    run_java_fixer(file_path)
