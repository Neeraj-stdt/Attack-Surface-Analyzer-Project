
from flask import Flask, jsonify

from database import init_db, get_scans, get_findings
from modules.scan_service import run_scan


app = Flask(__name__)

# Ensure database tables exist
init_db()


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "message": "Attack Surface Analyzer API is running"
    })


@app.route("/api/scan", methods=["POST"])
def start_scan():
    try:
        result = run_scan()

        return jsonify({
            "message": "Scan completed and saved",
            "scan_id": result["scan_id"],
            "scan_time": result["scan_time"],
            "hostname": result["hostname"],
            "total_findings": result["total_findings"],
            "risk_summary": result["risk_summary"],
            "component_counts": result["component_counts"]
        }), 201

    except Exception:
        app.logger.exception("Scan failed")

        return jsonify({
            "error": "Scan failed. Check the server terminal."
        }), 500


@app.route("/api/scans", methods=["GET"])
def list_scans():
    return jsonify({
        "scans": get_scans()
    })


@app.route("/api/scans/<int:scan_id>/findings", methods=["GET"])
def scan_findings(scan_id):
    findings = get_findings(scan_id)

    return jsonify({
        "scan_id": scan_id,
        "count": len(findings),
        "findings": findings
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
