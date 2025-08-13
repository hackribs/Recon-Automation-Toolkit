import subprocess
import sys
import os
import argparse
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

def run_command(command, input_data=None):
    print(f"[+] Running: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, input=input_data, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running command: {e}")
        print(e.stdout)
        print(e.stderr)
        sys.exit(1)

def check_tool_installed(tool):
    from shutil import which
    if which(tool) is None:
        print(f"[-] {tool} not found in PATH. Please install it and try again.")
        sys.exit(1)

def subdomain_enum_sublist3r(domain, output_file="subdomains.txt"):
    check_tool_installed("sublist3r")
    print("[*] Starting subdomain enumeration with Sublist3r...")
    run_command(["sublist3r", "-d", domain, "-o", output_file])
    print(f"[+] Subdomains saved to {output_file}")

    with open(output_file) as f:
        subdomains = [line.strip() for line in f if line.strip()]
    return subdomains

def subdomain_enum_amass(domain, output_file="subdomains.txt"):
    check_tool_installed("amass")
    print("[*] Starting subdomain enumeration with Amass...")
    run_command(["amass", "enum", "-d", domain, "-o", output_file, "-timeout", "10"])
    print(f"[+] Subdomains saved to {output_file}")

    with open(output_file) as f:
        subdomains = [line.strip() for line in f if line.strip()]
    return subdomains

def nmap_scan_host(host):
    xml_file = f"nmap_{host}.xml"
    try:
        run_command(["nmap", "-oX", xml_file, "-p-", "-T4", host])
        tree = ET.parse(xml_file)
        root = tree.getroot()
        ports = []
        for host_elem in root.findall("host"):
            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue
            for port in ports_elem.findall("port"):
                state = port.find("state").attrib.get("state")
                if state != "open":
                    continue
                portid = int(port.attrib.get("portid"))
                service_elem = port.find("service")
                service_name = service_elem.attrib.get("name") if service_elem is not None else "unknown"
                ports.append({"port": portid, "service": service_name})
        os.remove(xml_file)
        return host, ports
    except Exception as e:
        print(f"[-] Error scanning host {host}: {e}")
        return host, []

def port_scan_concurrent_nmap(hosts, max_workers=20):
    print("[*] Starting concurrent port scans with nmap...")
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(nmap_scan_host, host): host for host in hosts}
        for future in as_completed(futures):
            host, ports = future.result()
            results[host] = ports
    print("[+] Completed nmap port scans.")
    return results

def port_scan_masscan(hosts, ports="1-65535", rate=1000, output_file="masscan.json"):
    check_tool_installed("masscan")
    print(f"[*] Starting masscan on {len(hosts)} hosts for ports {ports} with rate {rate}pps...")

    # Write hosts to file
    hosts_file = "masscan_targets.txt"
    with open(hosts_file, "w") as f:
        for host in hosts:
            f.write(host + "\n")

    # Run masscan with JSON output
    cmd = [
        "masscan",
        "-iL", hosts_file,
        "-p", ports,
        "--rate", str(rate),
        "--wait", "0",
        "-oJ", output_file
    ]
    run_command(cmd)
    os.remove(hosts_file)

    # Parse masscan JSON output
    try:
        with open(output_file) as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] Failed to parse masscan output: {e}")
        return {}

    results = {}
    for entry in data:
        ip = entry.get("ip")
        port = entry.get("ports", [{}])[0].get("port")
        protocol = entry.get("ports", [{}])[0].get("proto")
        if ip and port:
            if ip not in results:
                results[ip] = []
            results[ip].append({"port": port, "service": protocol or "unknown"})

    print(f"[+] Completed masscan port scan. Results saved in {output_file}")
    return results

def http_probe_host(host):
    json_file = f"httpx_{host}.json"
    try:
        run_command([
            "httpx", "-silent", "-json", "-o", json_file, "-title", "-status-code", "-l", "-"
        ], input=host)
    except Exception as e:
        print(f"[-] Error probing host {host}: {e}")
        return []

    urls = []
    try:
        with open(json_file) as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                urls.append({
                    "url": data.get("url"),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "content_length": data.get("content_length", 0)
                })
        os.remove(json_file)
    except Exception as e:
        print(f"[-] Error parsing httpx output for {host}: {e}")

    return urls

def http_probe_concurrent(hosts, max_workers=20):
    print("[*] Starting concurrent HTTP probes...")
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(http_probe_host, host): host for host in hosts}
        for future in as_completed(futures):
            results.extend(future.result())
    print("[+] Completed HTTP probes.")
    return results

def generate_reports(domain, subdomains, ports, http_results, json_file="report.json", md_file="report.md"):
    report = {
        "domain": domain,
        "subdomains": subdomains,
        "port_scan": ports,
        "http_probe": http_results
    }

    with open(json_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] JSON report saved to {json_file}")

    md = f"# Scan Report for {domain}\n\n"

    md += "## Subdomains\n"
    if subdomains:
        md += "\n".join(f"- {sd}" for sd in subdomains) + "\n"
    else:
        md += "No subdomains found.\n"

    md += "\n## Port Scan Results\n"
    if ports:
        for host, port_list in ports.items():
            md += f"\n### {host}\n"
            if port_list:
                for p in port_list:
                    md += f"- Port {p['port']} ({p['service']})\n"
            else:
                md += "- No open ports found.\n"
    else:
        md += "No port scan data.\n"

    md += "\n## HTTP Probe Results\n"
    if http_results:
        for entry in http_results:
            title = entry.get("title") or "N/A"
            md += f"- {entry['url']} (Status: {entry['status_code']}, Title: {title})\n"
    else:
        md += "No HTTP services detected.\n"

    with open(md_file, "w") as f:
        f.write(md)
    print(f"[+] Markdown report saved to {md_file}")

def main():
    parser = argparse.ArgumentParser(description="Advanced concurrent scanner with Amass and Masscan support")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--subdomain-tool", choices=["amass", "sublist3r"], default="amass",
                        help="Tool to use for subdomain enumeration (default: amass)")
    parser.add_argument("--ports", action="store_true", help="Run port scan on discovered subdomains")
    parser.add_argument("--port-tool", choices=["nmap", "masscan"], default="masscan",
                        help="Tool to use for port scanning (default: masscan)")
    parser.add_argument("--http", action="store_true", help="Run HTTP probing on discovered subdomains")
    parser.add_argument("--report", default="report", help="Base name for output report files (JSON and MD)")
    parser.add_argument("--threads", type=int, default=20, help="Max concurrent threads for scanning")
    parser.add_argument("--masscan-ports", default="1-65535", help="Ports range for masscan (default: 1-65535)")
    parser.add_argument("--masscan-rate", type=int, default=1000, help="Rate for masscan packets per second (default: 1000)")

    args = parser.parse_args()

    subdomains = []
    ports = {}
    http_results = []

    if args.subdomains:
        if args.subdomain_tool == "amass":
            subdomains = subdomain_enum_amass(args.domain)
        else:
            subdomains = subdomain_enum_sublist3r(args.domain)

    if args.ports:
        if not subdomains:
            print("[-] Port scan requires subdomains. Run with --subdomains first or together.")
            sys.exit(1)

        if args.port_tool == "masscan":
            ports = port_scan_masscan(subdomains, ports=args.masscan_ports, rate=args.masscan_rate)
        else:
            ports = port_scan_concurrent_nmap(subdomains, max_workers=args.threads)

    if args.http:
        if not subdomains:
            print("[-] HTTP probing requires subdomains. Run with --subdomains first or together.")
            sys.exit(1)
        http_results = http_probe_concurrent(subdomains, max_workers=args.threads)

    if args.report:
        generate_reports(args.domain, subdomains, ports, http_results,
                         json_file=f"{args.report}.json", md_file=f"{args.report}.md")

if __name__ == "__main__":
    main()
