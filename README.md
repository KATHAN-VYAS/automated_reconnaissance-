## Automated Reconnaissance-
This project is a Python-based automation tool that simplifies the reconnaissance phase of cybersecurity assessments. By gathering domain-related information and presenting it in a detailed PDF report.

📌 Features:
DNS Record Enumeration: Extracts nameservers, IP addresses, and CNAME details.
Subdomain Discovery: Performs DNS brute-forcing to list subdomains.
Application Services Identification: Detects running services like Apache HTTP Server.
Port Scanning: Scans for open ports (e.g., FTP, HTTP, SMTP) and maps corresponding services.
Network Tracing: Tracks hops and measures latency to the target domain.
PDF Report Generation: Outputs findings in a structured PDF format.

🛠️ Modules Used:
Selenium: Automates data collection from web sources.
Nmap: For network scanning and open port detection.
Requests: Makes HTTP requests to gather information.
ReportLab: Generates comprehensive PDF reports.
dotenv: Ensures sensitive information like API keys are securely handled.

🧾 Example Report:
The tool generates a professional PDF report with information like DNS records, open ports, network traces, and application services. Here's a snippet from a sample report:

Domain: www.certifiedhacker.com
Open Ports: 21 (FTP), 80 (HTTP), 443 (HTTPS), etc.
DNS Records: Includes subdomains like mail, ftp, blog, and demo.

note: 
make sure to add your api key of dnsdumpster in the code and install required libraries

- for installing required libraries : 
1. install requirements.txt
2. run: pip install -r requirements.txt
