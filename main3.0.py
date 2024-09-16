import subprocess
import sys
import psutil
import platform

import self
# import nmap
# from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QProgressBar, QTextEdit, \
    QScrollArea
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import socket
import subprocess
import requests
from main import display_log


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


# Function to get system info
def get_system_info():
    info = {
        # Check for installed software and versions (e.g., using WMI for Windows)
        "OS": platform.platform(),
        "Version": platform.version(),
        "Architecture": platform.machine(),
        "Processor": platform.processor()
    }
    return info


# function to check system software versions
def check_software_versions():
    try:
        installed_software = subprocess.check_output("wmic product get name,version", shell=True, encoding='utf-8', errors='replace')
        return  installed_software
    except Exception as e:
        return f"Error: {e}"


# Function to scan open ports
# def scan_ports():
#     nm = nmap.PortScanner()
#     ip = get_device_ip()
#     print(f"{ip}")
#     nm.scan(f'{ip}', '1-1024')  # Localhost scan for open ports
#     # nm.scan('127.0.0.1', '1-1024')
#     open_ports = []
#     for host in nm.all_hosts():
#         for proto in nm[host].all_protocols():
#             lport = nm[host][proto].keys()
#             open_ports.extend(list(lport))
#     return open_ports


# def scan_ports_2():
#     nm = nmap.PortScanner()
#
#     # nm.scan(f'{ip}', '1-1024') # Localhost scan for open ports
#     nm.scan('127.0.0.1', '1-1024')
#     open_ports_2 = []
#     for host in nm.all_hosts():
#         for proto in nm[host].all_protocols():
#             lport = nm[host][proto].keys()
#             open_ports_2.extend(list(lport))
#     return open_ports_2


def check_antivirus():
    # Check if antivirus is running
    if "antivirus" not in (p.name().lower() for p in psutil.process_iter()):
        return f"Warning: No active antivirus detected. It is recommended to install one."
    else:
        return f"Antivirus detected and running."

def software_version():
    display_log("Checking for installed software versions...")
    try:
        installed_software = subprocess.check_output("wmic product get name,version", shell=True).decode()
        display_log(f"Installed Software:\n{installed_software}")
    except Exception as e:
        display_log(f"Error retrieving software information: {e}")

# A simple function to fetch CVE vulnerabilities for a specific software version
def fetch_vulnerabilities(software_name, version):
    # Mockup API call to a CVE or vulnerability database
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0{software_name}&version={version}"
    response = requests.get(url)
    if response.status_code == 200:
        vulnerabilities = response.json()
        return vulnerabilities  # List of known vulnerabilities
    else:
        return []


# Compare installed software versions against a vulnerability database
def check_installed_software(software_list):
    recommendations = []
    for software in software_list:
        name, version = software['name'], software['version']
        vulnerabilities = fetch_vulnerabilities(name, version)

        if vulnerabilities:
            recommendations.append({
                'software': name,
                'version': version,
                'vulnerabilities': vulnerabilities,
                'recommendation': f"Update {name} to a newer version to patch {len(vulnerabilities)} known vulnerabilities."
            })
    return recommendations


# Suggest security configurations based on the user's system
def suggest_security_settings(system_info):
    suggestions = []

    if not system_info.get('firewall_enabled', False):
        suggestions.append("Enable the firewall for better protection.")

    if system_info.get('user_privileges') == 'admin':
        suggestions.append("Consider using a non-admin account for daily tasks to reduce risk.")

    if not system_info.get('encryption_enabled', False):
        suggestions.append("Enable encryption for sensitive data.")

    return suggestions


# Update recommendations with critical details and explanations
def update_recommendations(recommendations):
    for rec in recommendations:
        # This could fetch details from a vulnerability description or performance updates
        rec['critical_details'] = f"Known vulnerabilities in {rec['software']} could lead to exploits."
        rec['performance_improvement'] = f"Performance improvements are also included in the update."
    return recommendations


# A function to execute a 1-click update
def one_click_update(software_name):
    try:
        # On Windows, you might use winget or PowerShell
        subprocess.run(["winget", "upgrade", software_name], check=True)

        # On Linux, it could be something like:
        # subprocess.run(["sudo", "apt-get", "install", "--only-upgrade", software_name], check=True)

        return f"{software_name} updated successfully."
    except subprocess.CalledProcessError as e:
        return f"Failed to update {software_name}: {str(e)}"



# def check_vulnerabilities(system_info):
#     # Simulated vulnerability check (replace with actual logic using CVE)
#     if "Windows" in system_info['OS']:
#         return ["Update OS to the latest version.", "Patch found vulnerabilities."]
#     return ["No critical vulnerabilities found."]


class AntiMalwareApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2E3440;
                color: #D8DEE9;
            }
            QPushButton {
                background-color: #4C566A;
                color: white;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #5E81AC;
            }
            QLabel, QTextEdit {
                color: #D8DEE9;
            }
        """)

        # Window setup
        self.setWindowTitle("Anti-Malware Security Suite")
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

        # Title
        title = QLabel("Anti-Malware Software")
        title.setFont(QFont('Arial', 24))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Scan button
        scan_button = QPushButton("Scan System")
        scan_button.clicked.connect(self.run_scan)
        layout.addWidget(scan_button)

        # Progress bar
        self.progress = QProgressBar(self)
        layout.addWidget(self.progress)

        # Result labels
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        self.result_area.setStyleSheet("background-color: #3B4252; color: #D8DEE9;")

        # Scroll Area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.result_area)

        layout.addWidget(scroll_area)
        self.setLayout(layout)

    def run_scan(self):
        # Simulated scan process
        self.progress.setValue(0)
        try:
         system_info = get_system_info()
         software_versions = check_software_versions()
         antivirus = check_antivirus()
         # open_ports = scan_ports()
         # open_ports_2 = scan_ports_2()
         # vulnerabilities = check_vulnerabilities(system_info)
         import time
         time.sleep(2)

         self.progress.setValue(100)
         self.result_area.setPlainText(f"System: {system_info['OS']}\n"
                                    f"Software Version: {software_versions}\n"
                                    f"Antivirus: {antivirus}"
                                    # f"Open Ports For {get_device_ip()}:{open_ports}\nOpen "
                                    # f"ports 2 for Host machine:{open_ports_2}\n"
                                           )
                                 # f"Recommendations: {'; '.join(vulnerabilities)}")
        except Exception as e:
          self.result_area.setPlainText(f"Error occurred: {e}")
          self.progress.setValue(0)

# Application loop
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntiMalwareApp()
    window.show()
    sys.exit(app.exec_())