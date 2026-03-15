from flask import Flask, render_template, jsonify
import os
import json

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

os.makedirs(REPORT_FOLDER, exist_ok=True)

def get_latest_report():
    """Return path to the latest report JSON, or None if none exist."""
    files = sorted(os.listdir(REPORT_FOLDER))
    if not files:
        return None
    return os.path.join(REPORT_FOLDER, files[-1])

@app.route("/")
def index():
    latest_report_path = get_latest_report()
    if not latest_report_path:
        return "No reports found!"
    with open(latest_report_path) as f:
        report = json.load(f)
    return render_template("index.html", report=report)

@app.route("/api")
def api():
    latest_report_path = get_latest_report()
    if not latest_report_path:
        return jsonify({"error": "No reports found!"})
    with open(latest_report_path) as f:
        report = json.load(f)
    return jsonify(report)

if __name__ == "__main__":
    app.run(debug=True)