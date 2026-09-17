import json
import urllib.parse
import http.server
import socketserver
from api.scan import analyze_url

class DevServerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="public", **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
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
        else:
            super().do_GET()

if __name__ == "__main__":
    PORT = 8000
    with socketserver.TCPServer(("", PORT), DevServerHandler) as httpd:
        print(f"ScanGuard running locally at http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")