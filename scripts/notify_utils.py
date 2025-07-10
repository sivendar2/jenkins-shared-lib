import requests

def notify_slack(webhook_url, pr_url):
    if not webhook_url:
        print("⚠️ Slack webhook URL not provided. Skipping notification.")
        return
    payload = {
        "text": f"✅ Security PR created: {pr_url}"
    }
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            print(f"❌ Slack notification failed: {response.text}")
        else:
            print("📢 Slack notified successfully.")
    except Exception as e:
        print(f"❌ Error sending Slack notification: {str(e)}")

def update_dashboard():
    print("📊 Updating dashboard... (placeholder)")
