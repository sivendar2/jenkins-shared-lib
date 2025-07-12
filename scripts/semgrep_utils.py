import subprocess
import os
import json
import sys

def run_command(cmd, cwd=None):
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"❌ Error running command: {result.stderr}")
        sys.exit(1)
    return result.stdout

def run_semgrep(semgrep_rules, repo_path):
    cmd = ["semgrep", "--config", semgrep_rules, "--json", repo_path]
    print(f"🔍 Running Semgrep command: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
    if proc.returncode != 0:
        print(f"❌ Semgrep failed:\n{proc.stderr}")
        sys.exit(1)

    # DEBUG: print raw output type and snippet
    print(f"📦 Raw Semgrep output type: {type(proc.stdout)}")
    print(f"📦 Raw Semgrep output preview:\n{proc.stdout[:500]}")

    try:
        findings = json.loads(proc.stdout)
        print(f"✅ Parsed Semgrep findings type: {type(findings)}")
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse Semgrep JSON: {e}")
        sys.exit(1)

    return findings

def suggest_fixes(findings):
    suggestions = []
    results = findings.get("results", [])
    print(f"🧠 Number of findings: {len(results)}")

    for item in results:
        try:
            path = item["path"]
            start_line = item["start"]["line"]
            message = item["extra"].get("message", "No message")

            print(f"📄 Finding in: {path} @ line {start_line} - {message}")
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
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    changed = False
    for i in range(len(lines)):
        # Fix JDBC Statement usage
        if "Statement" in lines[i] and "createStatement" in lines[i]:
            lines[i] = lines[i].replace("Statement", "PreparedStatement").replace("createStatement", "prepareStatement")
            changed = True

        # Fix JdbcTemplate + SQL Injection
        if "jdbcTemplate.query" in lines[i] and "+" in lines[i] and "\"" in lines[i]:
            # Naive fix: insert parameterized version
            lines[i] = '        return jdbcTemplate.query("SELECT * FROM employees WHERE department_id = ?", new BeanPropertyRowMapper<>(Employee.class), departmentName);\n'
            changed = True

    if changed:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f"✅ Applied fix in: {file_path}")
    else:
        print(f"⚠️ No fix applied to: {file_path}")

