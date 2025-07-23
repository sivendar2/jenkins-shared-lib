from flask import Flask, render_template, request, flash, redirect, url_for
import subprocess

app = Flask(__name__)
app.secret_key = 'your-secret-key'

CVE_FILE_PATH = "scripts/cves.csv"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        repo_url = request.form.get('repo_url')
        branch_name = request.form.get('branch_name', 'fix/security-auto')
        semgrep_rules = request.form.get('semgrep_rules', 'auto,rules/java-security')
        slack_webhook = request.form.get('slack_webhook', '')

        if not repo_url:
            flash('GitHub Repo URL is required', 'danger')
            return redirect(url_for('index'))

        # Build command with semgrep rules as a single comma-separated string (no splitting)
        cmd = [
            "python", "scripts/main.py",
            "--repo-url", repo_url,
            "--branch-name", branch_name,
            "--cve-file", CVE_FILE_PATH,
            "--semgrep-rules", semgrep_rules,  # pass exactly as is
            "--slack-webhook", slack_webhook
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True
            )
            flash('Scan completed successfully!', 'success')
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            flash(f'Error occurred: {error_msg}', 'danger')

        return redirect(url_for('index'))

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
