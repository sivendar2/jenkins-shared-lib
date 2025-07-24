from flask import Flask, render_template, request, Response, stream_with_context
import subprocess
import os
import sys
import time

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
    _ = request.args.get('uuid')  # ensures cache-busting

    cmd = [
        sys.executable, "-u", "scripts/main.py",
        "--repo-url", repo_url,
        "--branch-name", branch_name,
        "--cve-file", CVE_FILE_PATH,
        "--semgrep-rules", semgrep_rules,
        "--slack-webhook", slack_webhook
    ]

    env = os.environ.copy()
    env['PYTHONUTF8'] = '1'
    env['PYTHONUNBUFFERED'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'

    def generate():
        yield "data: 👋 Stream started...\n\n"

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace',
                env=env
            )

            for line in iter(process.stdout.readline, ''):
                if line.strip():
                    print("LOG:", line.strip())
                    yield f"data: {line.strip()}\n\n"

            process.stdout.close()
            process.wait()

            if process.returncode != 0:
                yield f"data: ❌ Subprocess exited with code {process.returncode}\n\n"
            else:
                yield "data: ✅ Scan complete!\n\n"

            time.sleep(0.3)  # let browser read last chunk
            return

        except Exception as e:
            yield f"data: ❌ Error: {str(e)}\n\n"
            return

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"  # or try "close" if needed
        }
    )


if __name__ == '__main__':
    app.run(debug=False, threaded=True)
