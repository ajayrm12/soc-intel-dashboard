from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route("/analyze", methods=["GET"])
def analyze():
    target = request.args.get("target")

    ip_api = requests.get(f"http://ip-api.com/json/{target}").json()

    return jsonify({
        "geo": ip_api
    })

if __name__ == "__main__":
    app.run()
