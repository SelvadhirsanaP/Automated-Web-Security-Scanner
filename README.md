
# Automated Web Security Scanner

## 1. Project Overview
The Automated Web Security Scanner is a Python-based tool that
checks basic website security configuration.

## 2. Problem Statement
Manually checking common HTTP security headers can be time-consuming.
This tool automates a small set of configuration checks and displays
recommendations for missing headers.

## 3. Objectives
- Validate the input URL.
- Check whether the final URL uses HTTPS.
- Inspect five common HTTP security headers.
- Display findings and recommendations.
- Generate TXT and JSON scan reports.
- Handle invalid URLs and connection errors.

## 4. Technologies Used
- Python
- Requests library
- JSON
- VS Code

## 5. Security Checks
- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy

## 6. How to Run
1. Install Python.
2. Install the Requests library using:
   python -m pip install requests
3. Run:
   python main.py
4. Enter a website URL when prompted.
5. Review the generated report files.

## 7. Output
The scanner displays HTTPS status, HTTP response status,
security header findings, severity labels, and recommendations.
It generates scan_report.txt and scan_report.json.

## 8. Limitations
This tool performs basic HTTP security configuration checks.
It does not perform a complete vulnerability assessment.
A missing header does not automatically mean a website is vulnerable.

## 9. Conclusion
The project demonstrates how Python can automate basic website
security checks and produce structured reports.
