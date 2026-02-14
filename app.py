from flask import Flask, render_template, request, jsonify
import requests
from urllib.parse import urlparse
import socket

app = Flask(__name__)


# -------------------------
# Risk Evaluation Helper
# -------------------------
def evaluate_risk(score):
    if score <= 2:
        return "Low"
    elif score <= 5:
        return "Medium"
    else:
        return "High"


# -------------------------
# Security Headers Check
# -------------------------
def check_security_headers(url):
    score = 0
    details = []

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]

        for header in required_headers:
            if header not in headers:
                score += 2
                details.append(f"{header} missing")

        risk = evaluate_risk(score)
        return {"risk": risk, "details": ", ".join(details) if details else "All major security headers present."}

    except:
        return {"risk": "Unknown", "details": "Could not analyze headers."}


# -------------------------
# Basic Port Scan
# -------------------------
def port_scan(url):
    score = 0
    details = []

    try:
        hostname = urlparse(url).hostname

        risky_ports = [21, 22, 23, 3306, 8080]
        open_ports = []

        for port in risky_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
                score += 2
            sock.close()

        risk = evaluate_risk(score)

        if open_ports:
            details = f"Open risky ports: {open_ports}"
        else:
            details = "No common risky ports detected."

        return {"risk": risk, "details": details}

    except:
        return {"risk": "Unknown", "details": "Port scan failed."}


# -------------------------
# SQL Injection Test
# -------------------------
def test_sql_injection(url):
    score = 0
    payload = "' OR '1'='1"

    try:
        test_url = url + "?id=" + payload
        response = requests.get(test_url, timeout=5)

        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            score += 4

        risk = evaluate_risk(score)

        return {
            "risk": risk,
            "details": "Potential SQL error patterns detected." if score else "No SQL injection patterns detected."
        }

    except:
        return {"risk": "Unknown", "details": "SQL test failed."}


# -------------------------
# XSS Test
# -------------------------
def test_xss(url):
    score = 0
    payload = "<script>alert(1)</script>"

    try:
        test_url = url + "?q=" + payload
        response = requests.get(test_url, timeout=5)

        if payload in response.text:
            score += 4

        risk = evaluate_risk(score)

        return {
            "risk": risk,
            "details": "Reflected XSS detected." if score else "No reflected XSS patterns detected."
        }

    except:
        return {"risk": "Unknown", "details": "XSS test failed."}


# -------------------------
# Routes
# -------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")

    if not target.startswith("http"):
        target = "http://" + target

    results = {
        "target": target,
        "sql_injection": test_sql_injection(target),
        "xss": test_xss(target),
        "security_headers": check_security_headers(target),
        "port_scan": port_scan(target)
    }

    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=False)

