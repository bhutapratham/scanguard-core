from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against man-in-the-middle attacks (HSTS).",
    "Content-Security-Policy": "Restricts resources to prevent XSS attacks (CSP).",
    "X-Frame-Options": "Prevents clickjacking by blocking unauthorized framing.",
    "X-Content-Type-Options": "Stops MIME-type sniffing attacks.",
    "Referrer-Policy": "Protects user privacy by controlling referrer data."
}

def analyze_url(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        res = requests.get(url, timeout=8, allow_redirects=True)
        headers = res.headers
    except Exception as e:
        return {"error": f"Failed to reach URL: {str(e)}"}

    score = 0
    total = len(SECURITY_HEADERS)
    details = []

    for header, desc in SECURITY_HEADERS.items():
        present = header in headers
        if present:
            score += 1
        details.append({
            "header": header,
            "present": present,
            "description": desc,
            "value": headers.get(header, "")
        })

    pct = (score / total) * 100
    if pct >= 80: grade = "A"
    elif pct >= 60: grade = "B"
    elif pct >= 40: grade = "C"
    elif pct >= 20: grade = "D"
    else: grade = "F"

    return {
        "url": url,
        "grade": grade,
        "score": score,
        "total": total,
        "percentage": pct,
        "details": details
    }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        target = query.get("url", [""])[0]

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        if not target:
            self.wfile.write(json.dumps({"error": "No URL provided"}).encode())
            return

        result = analyze_url(target)
        self.wfile.write(json.dumps(result).encode())