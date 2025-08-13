# Recon-Automation-Toolkit
A lightweight Python tool to automate reconnaissance tasks for bug bounty hunters, pentesters, and security researchers.
This toolkit combines powerful open-source utilities like Sublist3r for subdomain enumeration and Nmap for port scanning into a simple, easy-to-use script. It automates the repetitive early-stage information gathering so you can focus on what matters—finding vulnerabilities.

Features
------------------
*Subdomain enumeration using Sublist3r

*TCP port scanning with Nmap on discovered subdomains

*Clean, easy-to-read console output

*Designed for quick integration and customization

Getting Started
-----------------------
Simply provide a target domain, and the script will gather subdomains and scan their ports automatically.
-_- dont forget to install requirements using:
```bash
python3 check_dps.py
```
Who is this for?
--------------------
Bug bounty hunters looking to streamline recon

Penetration testers automating initial asset discovery

Security enthusiasts learning recon techniques

*Adjust --masscan-rate carefully depending on your bandwidth and target.

Usage examples:
----------------------------------------
Full scan with Amass + Masscan + HTTP probe:
```bash
python core_scan.py example.com --subdomains --ports --http --report myscan --threads 40 --masscan-rate 2000
```
Subdomains with Sublist3r + Nmap scan:
```bash
python core_scan.py example.com --subdomains --ports --subdomain-tool sublist3r --port-tool nmap
```

