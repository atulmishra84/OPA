from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
OPA_URL = "http://opa:8181/v1/data/logfilter/deny"

@app.route("/")
def home():
    return "OPA Log Filter API is running."

@app.route("/check-log", methods=["POST"])
def check_log():
    log_entry = request.json
    opa_response = requests.post(OPA_URL, json={"input": log_entry})
    result = opa_response.json()

    if "result" in result and result["result"]:
        return jsonify({
            "allowed": False,
            "reasons": result["result"]
        }), 403
    else:
        return jsonify({
            "allowed": True,
            "message": "Log entry is allowed"
        }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
