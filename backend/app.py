from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY")

@app.route("/")
def home():
    return "Backend is running 🚀"

@app.route("/analyze", methods=["GET"])
def analyze():
    target = request.args.get("target")

    # 🌍 GEO DATA
    geo_data = requests.get(f"http://ip-api.com/json/{target}").json()

    # 🛡️ VIRUSTOTAL DATA
    vt_data = {}
    if VT_API_KEY:
        try:
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            headers = {"x-apikey": VT_API_KEY}

            vt_response = requests.get(vt_url, headers=headers)
            vt_json = vt_response.json()

            stats = vt_json["data"]["attributes"]["last_analysis_stats"]

            vt_data = {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            }
        except:
            vt_data = {"error": "VT lookup failed"}

    return jsonify({
        "target": target,
        "geo": geo_data,
        "virustotal": vt_data
    })

if __name__ == "__main__":
    app.run()
