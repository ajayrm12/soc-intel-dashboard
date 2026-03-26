from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route("/")
def home():
    return "Backend is running"

@app.route("/analyze")
def analyze():
    target = request.args.get("target")
    return jsonify({"target": target, "status": "ok"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # VERY IMPORTANT
    app.run(host="0.0.0.0", port=port)
