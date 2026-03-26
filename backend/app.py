from flask import Flask, request, jsonify, send_from_directory
import requests
import os
import whois
from datetime import datetime

app = Flask(__name__, static_folder="../frontend")

VT_API_KEY = os.environ.get("VT_API_KEY")

@app.route("/")
def home():
    return "Backend is running 🚀"

# ✅ Serve frontend
@app.route("/dashboard")
def dashboard():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/analyze", methods=["GET"])
def analyze():
    target = request.args.get("target")

    # 🌍 GEO DATA
    geo_data = requests.get(f"http://ip-api.com/json/{target}").json()

    # 🛡️ VIRUSTOTAL
    vt_data = {"malicious": 0, "suspicious": 0, "harmless": 0}
    if VT_API_KEY:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            headers = {"x-apikey": VT_API_KEY}

            res = requests.get(url, headers=headers)
            data = res.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            vt_data = {
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "harmless": stats["harmless"]
            }
        except:
            pass

    # 🌐 DOMAIN AGE
    domain_age = "N/A"
    try:
        w = whois.whois(target)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            age_days = (datetime.now() - creation).days
            domain_age = f"{age_days} days"
    except:
        pass

    return jsonify({
        "target": target,
        "geo": geo_data,
        "virustotal": vt_data,
        "domain_age": domain_age
    })

if __name__ == "__main__":
    app.run()
