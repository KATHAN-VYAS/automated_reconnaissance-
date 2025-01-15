#importing libraries

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time
import requests
import nmap
import subprocess
import shlex
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import ssl
import socket

# api key for DNS dumpster
api_key = "----------------------------------" #your api key

#function doing webscrapping from nslookup
def scrape_dns_records(domain):
    
    options = Options()
    options.add_argument("--headless")  # Run in headless mode - No GUI for faster execution
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    try:
        # Open the nslookup.io DNS records page
        url = f"https://www.nslookup.io/domains/{domain}/dns-records/"
        driver.get(url)

        # Allow some time for the JavaScript content to load
        time.sleep(3)

        # Locate the <td> element with the email address and extract its text
        try:
            email_element = driver.find_element(By.XPATH, "//td[contains(text(), 'dnsadmin@')]")
            
            #var1 : email address of dmain
            email_address = email_element.text.strip()
            
        except Exception as e:
            email_address = "Not available"
        print(f"Email Address for {domain}: {email_address}")    
        
        # Locate the <td> element with the class "py-1" and extract its text
        try:
            td_element1 = driver.find_element(By.CLASS_NAME, "py-1")
            
            #var2 : ip address of domain
            ip_address = td_element1.text.strip().split(" ")[0].split("\n")[0]
           
            print(f"IP Address for {domain}: {ip_address}")
        except Exception as e:
            print(f"Could not find IP address for {domain}. Error: {e}")
    
    finally:
        # Close the WebDriver
        driver.quit()
    return ip_address, email_address

# Function to fetch DNS records using the DNSDumpster API
def fetch_dns_records(api_key, domain):
    
    api_url = f"https://api.dnsdumpster.com/domain/{domain}"  
    try:
        # Headers for authentication
        headers = {
            "X-API-Key": api_key
        }
        # Make a GET request to the API
        response = requests.get(api_url, headers=headers)
        # Raise an error if the request was not successful
        response.raise_for_status()
        # Parse the response JSON
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"Error fetching DNS records: {e}")
        return None

# function to fatch subdomains
def advanced_recon(target):
    
    dns_brute_results = [] 
    
    nm = nmap.PortScanner() 

    try:
        print(f"Performing advanced reconnaissance for {target}...")
        nm.scan(hosts=target, arguments='--script "dns-brute"')

        for host in nm.all_hosts():
            print(f"Host: {host}")
            if 'hostscript' in nm[host]:
                for script in nm[host]['hostscript']:
                    print(f"Script: {script['id']}")
                    output_lines = script['output'].splitlines()
                    # Parse the output to extract domain names and IP addresses
                    for line in output_lines:
                            if "-" in line:  # Identify lines with domain and IP
                                parts = line.split("-")
                                domain = parts[0].strip()  # Extract the domain name
                                ip_address = parts[1].strip()  # Extract the IP address
                                dns_brute_results.append({"domain": domain, "ip": ip_address})
                                print(f"Domain: {domain}, IP: {ip_address}")
    except Exception as e:
        print(f"Error: {e}")

    dns_brute_results = dns_brute_results[1:]
    return dns_brute_results

# function to trace hops
def trace_hops(domain):
    command = f"tracert {domain}"
    # stores avg time and ip of distance to dict
    hops_dict = {}
    #stores lines as arrays 
    main_arr = []
    n=0
    
    try:
        result = subprocess.run(command,shell = True, capture_output=True, text = True)
        if result.returncode == 0:
            new_result = result.stdout.splitlines()
            
            for lines in new_result:
                parts = shlex.split(lines)
                print(parts)
                main_arr.append(parts)
        else:
            print("command failed")
    except Exception as e:
        print("error:", e)

    path_arr = []
    path_dict = {}
    
    for i in range(4, len(main_arr)-2):
        path_arr.append(main_arr[i])
    for i in path_arr:
        try:
            time1 = float(i[1].replace("ms", "").strip())
            n+=1
        except Exception as e:
            continue
        try:
            time2 = float(i[3].replace("ms", "").strip())
            n+=1
        except Exception as e:
            continue
        try:
            time3 = float(i[5].replace("ms", "").strip())
            n+=1
        except Exception as e:
            continue
        
        avg_time = (time1 + time2 + time3) / n
        dest_ip = i[-1]
        path_dict[dest_ip] = avg_time
    return path_dict
    
# function to check open and closed ports
def port_scan(domain):
    
    nm = nmap.PortScanner()
    ports_range = "20-1000, 3306, 3389, 5000, 8080"
    nm.scan(domain, ports = ports_range, arguments = "-sS")

    #var 7,8 open ports and fitered ports
    open_ports = {}
    filtered_ports = {}

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            print("Protocol: %s" % proto)
            lport = list(nm[host][proto].keys())
            lport.sort()
            
            for port in lport:
                print("port: %s\tstate: %s" % (port, nm[host][proto][port]["state"]))
                
                if nm[host][proto][port]["state"]=="open":
                    open_ports[port]= nm[host][proto][port]["name"]
                if nm[host][proto][port]["state"] == "filtered":
                    filtered_ports[port] = nm[host][proto][port]["name"]
                
                if nm[host][proto][port]["state"] == "open":
                    print("Service: %s" % nm[host][proto][port]["name"])

    print(open_ports)
    print(filtered_ports)
    return open_ports, filtered_ports

def fetch_ssl_details(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert['issuer'])['organizationName'],
                    "valid_from": cert['notBefore'],
                    "valid_to": cert['notAfter']
                }
    except Exception as e:
        print(f"Error fetching SSL details: {e}")
        return None

def fetch_geolocation(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        return data.get("country"), data.get("region"), data.get("city")
    except Exception as e:
        print(f"Error fetching geolocation: {e}")
        return None
# User input for domain
domain = input("Enter the domain (e.g., example.com): ")

ip_address,email_address = scrape_dns_records(domain)

# Fetch DNS records
dns_records = fetch_dns_records(api_key, domain)

if dns_records:
    print("DNS Records:")
    print(dns_records)
    
a = dns_records["a"]
for i in a :
    host = i["host"]
    if host:
        print("Host: " + host)
    ips = i["ips"]
    
    #var3 : application service name
    try:
        app_service = ips[0]["banners"]["http"]["apps"]
    except Exception as e:
        app_service = "No information"
    #var: country
    try:
        country = ips[0]["country"]
    except Exception as e:
        country = "No information"
    print("country: ", country)
    #var: service
    if app_service:    
        print("App Service: ", app_service)
    #var4: service title
    try:
        service_title = ips[0]["banners"]["http"]["title"]
    except Exception as e:
        service_title = "No information"
    
    if service_title:
        print("Service Title: ", service_title)
    
ns = dns_records["ns"]

#var 5,6 ns host and ip address
ns_host = []
ns_host_ip = []

for i in ns:
    ns_host.append(i["host"])
    
    ips = i["ips"]
    for j in ips:
        ns_host_ip.append(j["ip"])
        
print(ns_host)
print(ns_host_ip)

dns_brute_results = advanced_recon(domain)

# Print the results
print("\nDNS Brute-force Results:")
for entry in dns_brute_results:
    print(f"Domain: {entry['domain']}, IP: {entry['ip']}")

hops_dict = trace_hops(domain)

open_ports, filtered_ports = port_scan(domain)
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
from reportlab.lib import colors

def create_pdf(email_add, ip_add, ns_host, ns_host_ip, app_service, service_title, dns_brute_results, hops_dict, open_ports, filtered_ports, domain):
    pdf_file = f"{domain}_details.pdf"

    country, region, city = fetch_geolocation(ip_add)
    # Set up PDF document
    doc = SimpleDocTemplate(pdf_file, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title = Paragraph(f"<b>Domain Details Report for: {domain}</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Add introduction
    intro_text = ("This document contains detailed reconnaissance information for the specified domain. "
                  "It includes DNS records, application services, brute-force results, and trace information, "
                  "which are critical for network analysis and security evaluations.")
    elements.append(Paragraph(intro_text, styles['BodyText']))
    elements.append(Spacer(1, 12))

    # Email and IP Address
    elements.append(Paragraph("<b>Contact Information</b>", styles['Heading2']))
    contact_data = [[f"Email Address: {email_add}"], [f"IP Address: {ip_add}"]]
    contact_table = Table(contact_data)
    contact_table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'LEFT')]))
    elements.append(contact_table)
    elements.append(Spacer(1, 12))

    # NS Records
    elements.append(Paragraph("<b>NS Hosts and IPs</b>", styles['Heading2']))
    ns_data = [["Host", "IP"]] + [[host, ip] for host, ip in zip(ns_host, ns_host_ip)]
    ns_table = Table(ns_data)
    ns_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT')
    ]))
    elements.append(ns_table)
    elements.append(Spacer(1, 12))
    
    # Geolocation Data
    elements.append(Paragraph("<b>Geolocation Information</b>", styles['Heading2']))
    geolocation_data = [
        ["Country", country if country else "Not available"],
        ["Region", region if region else "Not available"],
        ["City", city if city else "Not available"]
    ]
    geolocation_table = Table(geolocation_data)
    geolocation_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT')
    ]))
    elements.append(geolocation_table)
    elements.append(Spacer(1, 12))
    
    # SSL Certificate Details
    ssl_details = fetch_ssl_details(domain)
    if ssl_details:
        elements.append(Paragraph("<b>SSL Certificate Details</b>", styles['Heading2']))
        ssl_data = [
            ["Issuer", ssl_details["issuer"]],
            ["Valid From", ssl_details["valid_from"]],
            ["Valid To", ssl_details["valid_to"]]
        ]
        ssl_table = Table(ssl_data)
        ssl_table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'LEFT')]))
        elements.append(ssl_table)
        elements.append(Spacer(1, 12))
        
    

    # App Service and Service Title
    elements.append(Paragraph("<b>Application Service Information</b>", styles['Heading2']))
    app_data = [[f"App Service: {app_service}"], [f"Service Title: {service_title}"]]
    app_table = Table(app_data)
    app_table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'LEFT')]))
    elements.append(app_table)
    elements.append(Spacer(1, 12))

    # DNS Brute-force Results
    elements.append(Paragraph("<b>DNS Brute-force Results</b>", styles['Heading2']))
    brute_data = [["Domain", "IP"]] + [[entry['domain'], entry['ip']] for entry in dns_brute_results]
    brute_table = Table(brute_data)
    brute_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT')
    ]))
    elements.append(brute_table)
    elements.append(Spacer(1, 12))

    # Trace Hops
    elements.append(Paragraph("<b>Trace Hops</b>", styles['Heading2']))
    hops_data = [["IP", "Avg Time (ms)"]] + [[ip, f"{avg_time:.2f}"] for ip, avg_time in hops_dict.items()]
    hops_table = Table(hops_data)
    hops_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT')
    ]))
    elements.append(hops_table)
    elements.append(Spacer(1, 12))

    # Open and Filtered Ports
    elements.append(Paragraph("<b>Open Ports Information</b>", styles['Heading2']))
    ports_data = [["Port", "Service"]] + [[port, service] for port, service in open_ports.items()]
    ports_table = Table(ports_data)
    ports_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT')
    ]))
    elements.append(ports_table)
    elements.append(Spacer(1, 12))
    

    if filtered_ports:
        filtered_data = [["Port", "Service"]] + [[port, service] for port, service in filtered_ports.items()]
        filtered_table = Table(filtered_data)
        filtered_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT')
        ]))
        elements.append(Paragraph("<b>Filtered Ports</b>", styles['Heading2']))
        elements.append(filtered_table)
        elements.append(Spacer(1, 12))

    # Footer with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"<i>Generated on: {timestamp}</i>", styles['BodyText']))

    # Build PDF
    doc.build(elements)
    print(f"PDF saved as {pdf_file}")

# Generate the PDF report
create_pdf(email_address, ip_address, ns_host, ns_host_ip, app_service, service_title, dns_brute_results, hops_dict, open_ports, filtered_ports, domain)
