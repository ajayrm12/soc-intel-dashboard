from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route("/")
def home():
    return "Backend is running 🚀"

@app.route("/analyze", methods=["GET"])
def analyze():
    target = request.args.get("target")

    ip_data = requests.get(f"http://ip-api.com/json/{target}").json()

    return jsonify({
        "target": target,
        "geo": ip_data
    })

if __name__ == "__main__":
    app.run()
