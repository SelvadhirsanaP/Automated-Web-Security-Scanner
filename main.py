
import requests
import json
from urllib.parse import urlparse
from datetime import datetime

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "recommendation": "Helps enforce HTTPS connections."
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "recommendation": "Helps reduce certain content injection risks."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "recommendation": "Helps prevent MIME-type sniffing."
    },
    "X-Frame-Options": {
        "severity": "Low",
        "recommendation": "Helps reduce clickjacking risks."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "recommendation": "Controls how much referrer information is shared."
    }
}


def scan_website(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print("Invalid URL. Enter a complete http:// or https:// URL.")
        return

    findings = []

    report = {
        "target": url,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "http_status": None,
        "final_url": None,
        "https_enabled": False,
        "findings": []
    }

    print("\nAUTOMATED WEB SECURITY SCANNER")
    print("=" * 50)
    print("Target:", url)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        report["http_status"] = response.status_code
        report["final_url"] = response.url
        report["https_enabled"] = response.url.startswith("https://")

        print("HTTP Status Code:", response.status_code)
        print("Final URL:", response.url)

        if report["https_enabled"]:
            print("[PASS] HTTPS is used")
        else:
            print("[WARN] Final URL does not use HTTPS")

        print("\nSECURITY HEADER CHECKS")
        print("-" * 50)

        for header, details in SECURITY_HEADERS.items():
            if header in response.headers:
                status = "PRESENT"
                severity = "Informational"
                recommendation = "Header is present."
            else:
                status = "MISSING"
                severity = details["severity"]
                recommendation = details["recommendation"]

            finding = {
                "header": header,
                "status": status,
                "severity": severity,
                "recommendation": recommendation
            }

            findings.append(finding)

            print(f"[{status}] {header}")
            if status == "MISSING":
                print("  Severity:", severity)
                print("  Recommendation:", recommendation)

        report["findings"] = findings

        missing_count = sum(
            1 for item in findings if item["status"] == "MISSING"
        )

        report["missing_headers_count"] = missing_count
        report["present_headers_count"] = len(findings) - missing_count

        print("\nSCAN SUMMARY")
        print("-" * 50)
        print("Headers checked:", len(findings))
        print("Present:", report["present_headers_count"])
        print("Missing:", report["missing_headers_count"])

    except requests.RequestException as error:
        report["error"] = str(error)
        print("Unable to complete scan:", error)

    with open("scan_report.txt", "w", encoding="utf-8") as file:
        file.write("AUTOMATED WEB SECURITY SCANNER\n")
        file.write(json.dumps(report, indent=4))

    with open("scan_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nReports saved:")
    print("- scan_report.txt")
    print("- scan_report.json")


if __name__ == "__main__":
    target = input("Enter a website URL: ").strip()
    scan_website(target)
