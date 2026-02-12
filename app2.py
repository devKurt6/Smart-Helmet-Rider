from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # allow all origins

# Store latest GPS data from ESP32
latest_data = {
    "lat": None,
    "lng": None,
    "speed": None,
    "sat": None,
    "alt": None,

    "hour": None,
    "minute": None,
    "second": None,
    "day": None,
    "month": None,
    "year": None,

    "alcohol_raw": None,
    "alcohol_status": None
}


# Serve dashboard HTML
@app.route("/")
def index():
    return render_template("index.html")

# API for ESP32 to POST GPS data
@app.route("/api/gps", methods=["POST"])
def receive_gps():
    global latest_data
    data = request.json
    latest_data = {
        "lat": data.get("lat"),
        "lng": data.get("lng"),
        "speed": data.get("speed"),
        "sat": data.get("sat"),
        "alt": data.get("alt"),

        "hour": data.get("hour"),
        "minute": data.get("minute"),
        "second": data.get("second"),
        "day": data.get("day"),
        "month": data.get("month"),
        "year": data.get("year"),

        "alcohol_raw": data.get("alcohol_raw"),
        "alcohol_status": data.get("alcohol_status")
    }

    print("Received GPS:", latest_data)
    return jsonify({"status": "ok"}), 200

# API for dashboard to GET latest GPS data
@app.route("/api/gps", methods=["GET"])
def get_gps():
    return jsonify(latest_data), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
