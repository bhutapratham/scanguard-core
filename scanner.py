import sys
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against man-in-the-middle attacks (HSTS).",
    "Content-Security-Policy": "Restricts resources to prevent XSS attacks (CSP).",
    "X-Frame-Options": "Prevents clickjacking by blocking unauthorized framing.",
    "X-Content-Type-Options": "Stops MIME-type sniffing attacks.",
    "Referrer-Policy": "Protects user privacy by controlling referrer data."
}

def scan_url(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n--- Scanning: {url} ---")
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        print(f"Error reaching {url}: {e}")
        sys.exit(1)

    score = 0
    total = len(SECURITY_HEADERS)
    missing = []
    present = []

    for header, description in SECURITY_HEADERS.items():
        if header in headers:
            score += 1
            present.append(header)
        else:
            missing.append((header, description))

    percentage = (score / total) * 100
    if percentage >= 80:
        grade = "A"
    elif percentage >= 60:
        grade = "B"
    elif percentage >= 40:
        grade = "C"
    elif percentage >= 20:
        grade = "D"
    else:
        grade = "F"

    print(f"Security Grade: {grade} ({score}/{total} headers present)\n")
    
    print("Found Headers:")
    for h in present:
        print(f"  [PASS] {h}")

    print("\nMissing Headers:")
    for h, desc in missing:
        print(f"  [FAIL] {h} -> {desc}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[-1].strip()
    else:
        target = input("Enter website URL to scan (e.g., github.com): ").strip()
    if target:
        scan_url(target)