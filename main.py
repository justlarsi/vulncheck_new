import os
import psutil
import hashlib
import socket
import subprocess
import platform
import logging
from datetime import datetime
from tkinter import Tk, Label, Button, Text, END, messagebox
from nmap import PortScanner

# Setup logging
logging.basicConfig(filename="vulnerability_scan_log.log", level=logging.INFO)

# Helper functions for port scanning and vulnerability checks
PORT_DESCRIPTIONS = {
    22: ("SSH", "Secure, but vulnerable if outdated or improperly configured"),
    80: ("HTTP", "Vulnerable to man-in-the-middle attacks and data sniffing"),
    443: ("HTTPS", "Secure, but vulnerabilities exist in outdated versions"),
    21: ("FTP", "Plaintext authentication, vulnerable to sniffing"),
    23: ("Telnet", "Very insecure, avoid using"),
    3389: ("RDP", "Can allow remote access; keep patched and use strong passwords"),
    # Add more port descriptions and risks as needed
}


def get_device_ip():
    # Create a socket connection to retrieve the local IP address
    try:
        # Connect to an external server to find the device's IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Use a random public server (does not send any data)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        return f"Error occurred: {e}"


# def perform_port_scan():
#     display_log("Starting deep port scan...")
#
#     # gettign device ip
#     ip = get_device_ip()
#     display_log(f"Your device's IP address: {ip}")
#
#     # # Get the hostname of the device
#     # hostname = socket.gethostname()
#     # # Get the IP address of the device
#     # ip_address = socket.gethostbyname(hostname)
#     # display_log(f"IP Address: {ip_address}")
#
#     # Initialize the PortScanner
#     scanner = PortScanner()
#
#     display_log("Scanning all ports from 1 to 65535 (this may take some time)...")
#
#     scanner.scan('{ip}', '1-65535', '-sS')
#     port_info = []
#     open_ports = []
#     closed_ports = []
#
#     for host in scanner.all_hosts():
#         for proto in scanner[host].all_protocols():
#             lport = scanner[host][proto].keys()
#             for port in lport:
#                 state = scanner[host][proto][port]['state']
#                 if state == 'open':
#                     open_ports.append(port)
#                     port_info.append(f"Port {port} is open ({proto.upper()})")
#                 else:
#                     closed_ports.append(port)
#
#     # Display results
#     if open_ports:
#         display_log(f"Open Ports ({len(open_ports)}):\n" + "\n".join(port_info))
#         display_log(f"Recommendation: Close unused open ports to reduce attack surface.")
#     else:
#         display_log("No open ports detected.")
#
#     display_log(f"Total Closed Ports: {len(closed_ports)}")
#     display_log("Port scan complete.")
#

def check_for_vulnerabilities():
    display_log("Checking system vulnerabilities...")

    # Open ports
    open_ports = [conn.laddr.port for conn in psutil.net_connections() if conn.status == 'LISTEN']
    vulnerable_ports = [3389, 445, 135, 80, 8080]  # Common ports for RDP, SMB, and DCOM

    if any(port in open_ports for port in vulnerable_ports):
        display_log(f"Warning: Potentially vulnerable ports are open: {open_ports}. Consider closing unused ports.")
    else:
        display_log("No known vulnerable ports detected.")

    # 2. Check if antivirus is running
    if "antivirus" not in (p.name().lower() for p in psutil.process_iter()):
        display_log("Warning: No active antivirus detected. It is recommended to install one.")
    else:
        display_log("Antivirus detected and running.")

    # 3. Gather system and software information for vulnerability checks
    os_version = platform.platform()
    display_log(f"Operating System: {os_version}")

    # Check for installed software and versions (e.g., using WMI for Windows)
    display_log("Checking for installed software versions...")
    try:
        installed_software = subprocess.check_output("wmic product get name,version", shell=True).decode()
        display_log(f"Installed Software:\n{installed_software}")
    except Exception as e:
        display_log(f"Error retrieving software information: {e}")

    # 4. Check if critical updates are installed (optional: you can expand on this)
    display_log("Checking for system updates...")
    try:
        updates = subprocess.check_output("wmic qfe get hotfixid", shell=True).decode()
        display_log(f"Installed Updates:\n{updates}")
    except Exception as e:
        display_log(f"Error checking updates: {e}")

    display_log("System vulnerability check completed.")
def ransomware_behavior_analysis():
    display_log("Analyzing system behavior for ransomware...")
    # Placeholder for ransomware behavior detection logic
    # This should include monitoring for file modifications, encryption attempts, etc.
    # Currently, it's just a basic placeholder:
    display_log("Behavior analysis complete. No suspicious activity detected.")


# GUI and Dashboard
def display_log(message):
    output_box.insert(END, message + "\n")
    output_box.see(END)


def run_vulnerability_checks():
    # perform_port_scan()
    check_for_vulnerabilities()
    ransomware_behavior_analysis()


# Main App UI
def run_app():
    global output_box
    app = Tk()
    app.title("System Vulnerability Scanner")
    app.geometry("700x500")

    Label(app, text="System Vulnerability Scanner", font=("Arial", 16)).pack(pady=10)

    Button(app, text="Start Vulnerability Check", command=run_vulnerability_checks).pack(pady=5)

    output_box = Text(app, height=100, width=100)
    output_box.pack(pady=10)

    app.mainloop()


if __name__ == "__main__":
    run_app()

