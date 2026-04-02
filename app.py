from flask import Flask, render_template
import json
from collections import Counter

app = Flask(__name__)

LOG_FILE = "../data/cowrie.json"

@app.route("/")
def home():
    ips = Counter()
    commands = Counter()

    try:
        with open(LOG_FILE) as f:
            for line in f:
                data = json.loads(line)

                if "src_ip" in data:
                    ips[data["src_ip"]] += 1

                if data.get("eventid") == "cowrie.command.input":
                    commands[data.get("input")] += 1

    except FileNotFoundError:
        return "No logs found. Generate attack first!"

    top_ips = ips.most_common(10)
    top_cmds = commands.most_common(10)

    html = "<h1>🚨 Honeypot Dashboard</h1>"

    html += "<h2>Top Attacker IPs</h2><ul>"
    for ip, count in top_ips:
        html += f"<li>{ip} → {count}</li>"
    html += "</ul>"

    html += "<h2>Top Commands</h2><ul>"
    for cmd, count in top_cmds:
        html += f"<li>{cmd} → {count}</li>"
    html += "</ul>"

    return html

app.run(host="0.0.0.0", port=5000)
