import subprocess
import sys
from shutil import which

def check_command(cmd):
    return which(cmd) is not None

def install_sublist3r():
    print("[*] Installing sublist3r via pip...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "sublist3r"])

def main():
    tools = {
        "amass": False,
        "masscan": False,
        "nmap": False,
        "httpx": False,
        "sublist3r": False
    }

    print("Checking required tools...")
    for tool in tools.keys():
        if check_command(tool):
            print(f"[+] {tool} found.")
            tools[tool] = True
        else:
            print(f"[-] {tool} NOT found.")

    if not tools["sublist3r"]:
        try:
            install_sublist3r()
            tools["sublist3r"] = True
        except Exception as e:
            print(f"[-] Failed to install sublist3r automatically: {e}")

    print("\nSummary:")
    for tool, installed in tools.items():
        print(f"  {tool}: {'Installed' if installed else 'Missing'}")

    missing = [t for t, installed in tools.items() if not installed]
    if missing:
        print("\nPlease manually install the missing tools:")
        if "amass" in missing:
            print(" - Amass: https://github.com/OWASP/Amass#installation")
        if "masscan" in missing:
            print(" - Masscan: https://github.com/robertdavidgraham/masscan#installation")
        if "nmap" in missing:
            print(" - Nmap: https://nmap.org/download.html")
        if "httpx" in missing:
            print(" - Httpx: https://github.com/projectdiscovery/httpx#installation")

    else:
        print("\nAll required tools are installed. You're good to go!")

if __name__ == "__main__":
    main()
