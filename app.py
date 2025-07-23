from flask import Flask, render_template, request, Response
import subprocess
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key'

CVE_FILE_PATH = "scripts/cves.csv"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stream')
def stream():
    repo_url = request.args.get('repo_url')
    branch_name = request.args.get('branch_name', 'fix/security-auto')
    semgrep_rules = request.args.get('semgrep_rules', 'auto,rules/java-security')
    slack_webhook = request.args.get('slack_webhook', '')

    cmd = [
    "python", "-u", "scripts/main.py",  # ← this line had the typo
    "--repo-url", repo_url,
    "--branch-name", branch_name,
    "--cve-file", CVE_FILE_PATH,
    "--semgrep-rules", semgrep_rules,
    "--slack-webhook", slack_webhook
]

    env = os.environ.copy()
    env['PYTHONUTF8'] = '1'

    def generate():
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1, 
                env=env
            )
            for line in iter(process.stdout.readline, ''):
                if line:
                    yield f"data: {line.strip()}\n\n"
            yield "data: ✅ Scan complete!\n\n"
        except Exception as e:
            yield f"data: ❌ Error: {str(e)}\n\n"

    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True)
