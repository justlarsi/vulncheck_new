import logging
import os
import socket
import subprocess
import sys
import psutil
import platform
import json
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QProgressBar, QTextEdit, \
    QScrollArea, QFrame, QMessageBox
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMetaObject
from functools import partial

from nmap import nmap


# Function to get system info
def get_system_info():
    return {
        "OS": platform.platform(),
        "Version": platform.version(),
        "Architecture": platform.machine(),
        "Processor": platform.processor()
    }


# Function to check installed software versions
def check_software():
    try:
        return subprocess.check_output("wmic product get name,version", shell=True, encoding='utf-8', errors='replace')
    except Exception as e:
        return f"Error: {e}"
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

# Function to scan open ports
def scan_ports():
    nm = nmap.PortScanner()
    ip = get_device_ip()
    print(f"{ip}")
    nm.scan(f'{ip}', '1-1024')  # Localhost scan for open ports
    # nm.scan('127.0.0.1', '1-1024')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            open_ports.extend(list(lport))
    return open_ports


def scan_ports_2():
    nm = nmap.PortScanner()

    # nm.scan(f'{ip}', '1-1024') # Localhost scan for open ports
    nm.scan('127.0.0.1', '1-1024')
    open_ports_2 = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            open_ports_2.extend(list(lport))
    return open_ports_2


def check_antivirus():
    if "antivirus" not in (p.name().lower() for p in psutil.process_iter()):
        return "Warning: No active antivirus detected."
    return "Antivirus detected and running."


def load_vulnerabilities_from_file(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        return f"Error loading vulnerabilities: {e}"


def analyze_vulnerabilities(software, vulnerabilities):
    software_vulnerabilities = []
    for vulnerability in vulnerabilities.get('CVE_Items', []):
        cve_id = vulnerability['cve']['CVE_data_meta']['ID']
        description = vulnerability['cve']['description']['description_data'][0]['value']
        cvss_score = None
        severity = "Low"

        if 'impact' in vulnerability:
            if 'baseMetricV2' in vulnerability['impact']:
                cvss_score = vulnerability['impact']['baseMetricV2']['cvssV2']['baseScore']
            elif 'baseMetricV3' in vulnerability['impact']:
                cvss_score = vulnerability['impact']['baseMetricV3']['cvssV3']['baseScore']

        cvss_score = cvss_score or 0.0  # Default to 0 if no score
        if cvss_score >= 9.0:
            severity = "Critical"
        elif cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"

        software_vulnerabilities.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity
        })

    return sorted(software_vulnerabilities, key=lambda x: x['cvss_score'], reverse=True)[:3]


def check_software_versions():
    try:
        installed_software = subprocess.check_output("wmic product get name,version", shell=True, encoding='utf-8', errors='replace')
        software_list = []
        lines = installed_software.splitlines()
        for line in lines[1:]:
            if line.strip():
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    name, version = parts[0].strip(), parts[1].strip()
                    software_list.append({"name": name, "version": version})
        return software_list
    except Exception as e:
        return f"Error: {e}"


def check_vulnerabilities(installed_software, vuln_file):
    vulnerabilities = load_vulnerabilities_from_file(vuln_file)
    software_vulnerabilities = []

    if isinstance(vulnerabilities, dict):
        for software in installed_software:
            severe_vulnerabilities = analyze_vulnerabilities(software, vulnerabilities)
            if severe_vulnerabilities:
                software_vulnerabilities.append({
                    "software": software['name'],
                    "version": software['version'],
                    "vulnerabilities": severe_vulnerabilities
                })
        return sorted(software_vulnerabilities, key=lambda x: x['vulnerabilities'][0]['cvss_score'], reverse=True)[:15]
    return []


class UpdateWorker(QThread):
    update_complete = pyqtSignal(str, str)  # Signal to emit update completion message and version

    def __init__(self, software_name):
        super().__init__()
        self.software_name = software_name

    def run(self):
        try:
            updated_version = None
            if self.software_name.lower() == "python":
                updated_version = self.update_python()
            elif self.software_name.lower() == "microsoft windows":
                updated_version = self.update_windows_os()
            elif self.software_name.lower() == "node.js":
                updated_version = self.update_nodejs()
            elif self.software_name.lower() == "java":
                updated_version = self.update_java()
            elif self.software_name.lower() == "rust":
                updated_version = self.update_rust()
            elif self.software_name.lower() == "docker":
                updated_version = self.update_docker()
            elif platform.system().lower() == "linux":
                updated_version = self.update_linux_package()

            if not updated_version:
                updated_version = self.update_with_winget()  # Fallback to winget for general apps

            self.update_complete.emit(f"{self.software_name} update successful.", updated_version)
        except Exception as e:
            self.update_complete.emit(f"Update failed for {self.software_name}: {str(e)}", "Unknown Version")

    def update_with_winget(self):
        try:
            update_command = f'winget upgrade --id "{self.software_name}"'
            update_process = subprocess.run(update_command, shell=True, capture_output=True, text=True)

            if update_process.returncode != 0:
                raise Exception(f"Update failed: {update_process.stderr}")

            return self.get_updated_version(self.software_name)
        except Exception as e:
            raise Exception(f"Update failed for {self.software_name}: {str(e)}")

    def update_python(self):
        try:
            # Configure logging for better debug information
            logging.basicConfig(filename='update_python_packages.log', level=logging.INFO,
                                format='%(asctime)s - %(levelname)s - %(message)s')

            # Get the current Python version
            current_version = sys.version.split()[0]

            # Update Python to the latest version using pyupgrade
            logging.info("Updating Python to the latest version...")
            subprocess.run(["py", "-m", "pip", "install", "--upgrade", "pip"], capture_output=True, text=True,
                           check=True)
            subprocess.run(["py", "-m", "pip", "install", "--upgrade", "setuptools"], capture_output=True, text=True,
                           check=True)

            # Get the updated Python version
            updated_version = \
            subprocess.run(["python", "--version"], capture_output=True, text=True, check=True).stdout.strip().split()[
                1]

            # Check if the update was successful
            if updated_version != current_version:
                self.update_complete.emit(f"Python updated successfully from {current_version} to {updated_version}.",
                                          updated_version)
            else:
                self.update_complete.emit(f"Python not updated. Current version matches with latest version. Please wait until a new version is released and then try again: {current_version}.", current_version)

        except subprocess.CalledProcessError as e:
            error_message = f"Update process failed: {e.stderr}"
            logging.error(error_message)
            self.update_complete.emit(error_message, "Unknown Version")
        except Exception as e:
            # Catch all unexpected errors
            error_message = f"Unexpected error during update: {str(e)}"
            logging.error(error_message)
            self.update_complete.emit(error_message, "Unknown Version")
    def update_windows_os(self):
        try:
            update_command = 'powershell "Get-WindowsUpdate -Install -AcceptAll"'
            update_process = subprocess.run(update_command, shell=True, capture_output=True, text=True)

            if update_process.returncode != 0:
                raise Exception(f"Windows Update failed: {update_process.stderr}")

            return "Windows OS updated successfully."
        except Exception as e:
            raise Exception(f"Update failed for Windows OS: {str(e)}")

    def update_nodejs(self):
        try:
            # Update npm itself
            subprocess.run("npm install -g npm", shell=True, capture_output=True, text=True)
            update_process = subprocess.run("npm outdated -g", shell=True, capture_output=True, text=True)

            outdated_packages = update_process.stdout.splitlines()
            updated_packages = []
            for pkg in outdated_packages:
                package_name = pkg.split()[0]
                subprocess.run(f"npm install -g {package_name}", shell=True, capture_output=True, text=True)
                updated_packages.append(package_name)

            return ", ".join(updated_packages) if updated_packages else "No npm packages updated."
        except Exception as e:
            raise Exception(f"Update failed for Node.js: {str(e)}")

    def update_java(self):
        try:
            update_command = "sdk update java"
            update_process = subprocess.run(update_command, shell=True, capture_output=True, text=True)

            if update_process.returncode != 0:
                raise Exception(f"Java update failed: {update_process.stderr}")

            return "Java updated successfully."
        except Exception as e:
            raise Exception(f"Update failed for Java: {str(e)}")

    def update_rust(self):
        try:
            subprocess.run("rustup update", shell=True, capture_output=True, text=True)
            return "Rust toolchain updated successfully."
        except Exception as e:
            raise Exception(f"Update failed for Rust: {str(e)}")

    def update_docker(self):
        try:
            subprocess.run("docker system prune -f", shell=True, capture_output=True, text=True)
            subprocess.run("docker images | grep -v REPOSITORY | awk '{print $1\":\"$2}' | xargs -I {} docker pull {}", shell=True, capture_output=True, text=True)
            return "Docker images updated successfully."
        except Exception as e:
            raise Exception(f"Update failed for Docker: {str(e)}")

    def update_office(self):
        try:
            # Office 2013 or other Office versions
            update_command = 'powershell "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search($null).Updates | foreach { $_.Install() }"'
            update_process = subprocess.run(update_command, shell=True, capture_output=True, text=True)

            if update_process.returncode != 0:
                raise Exception(f"Microsoft Office update failed: {update_process.stderr}")

            return "Microsoft Office updated successfully."
        except Exception as e:
            raise Exception(f"Update failed for Microsoft Office: {str(e)}")

    def update_linux_package(self):
        try:
            distro = platform.linux_distribution()[0].lower()
            if "ubuntu" in distro or "debian" in distro:
                update_command = "sudo apt update && sudo apt upgrade -y"
            elif "fedora" in distro or "centos" in distro:
                update_command = "sudo yum update -y"
            else:
                return "Unsupported Linux distro for automated updates."

            subprocess.run(update_command, shell=True, capture_output=True, text=True)
            return f"{distro.capitalize()} packages updated successfully."
        except Exception as e:
            raise Exception(f"Update failed for Linux package: {str(e)}")

    def get_updated_version(self, software_name):
        try:
            version_command = f'winget show --id "{software_name}"'
            version_process = subprocess.run(version_command, shell=True, capture_output=True, text=True)

            if version_process.returncode == 0:
                # Assuming the output contains version info in a specific format
                for line in version_process.stdout.splitlines():
                    if "Version" in line:
                        return line.split(":")[-1].strip()
            return "Unknown Version"
        except Exception:
            return "Unknown Version"


class AntiMalwareApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Anti-Malware Security Suite")
        self.setGeometry(100, 100, 900, 700)  # Increased size for better layout
        self.setStyleSheet("""
            QWidget {
                background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #0A0F0D, stop:0.5 #0F5734, stop:1 #1F8C56);
                color: #E0E0E0;
                font-family: Arial, sans-serif;
            }
            QPushButton {
                background-color: #1F8C56;
                color: #FFFFFF;
                padding: 12px 20px;
                font-size: 16px;
                border: 2px solid #145C37;
                border-radius: 8px;
                transition: background-color 0.3s, box-shadow 0.3s;
            }
            QPushButton:hover {
                background-color: #17A26A;
                box-shadow: 0px 0px 10px #17A26A;
            }
            QLabel {
                font-size: 18px;
                color: #E0E0E0;
                padding: 10px;
                border: none;
            }
            QProgressBar {
                border: 2px solid #1F8C56;
                border-radius: 8px;
                text-align: center;
                font-size: 14px;
                color: #FFFFFF;
                background-color: #0A0F0D;
                padding: 5px;
            }
            QProgressBar::chunk {
                background-color: #1F8C56;
                width: 20px;
                margin: 1px;
            }
            QScrollArea {
                border: 1px solid #4C566A;
                border-radius: 10px;
                background-color: #0A0F0D;
            }
            QScrollBar:vertical {
                background: #0A0F0D;
                width: 18px;
                margin: 16px 0 16px 0;
                border-radius: 8px;
            }
            QScrollBar::handle:vertical {
                background: #1F8C56;
                min-height: 800px;
                
                border-radius: 8px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
                border: none;
            }
        """)

        main_layout = QVBoxLayout()

        # Title
        title = QLabel("Anti-Malware Software")
        title.setFont(QFont('Arial', 28, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #E0E0E0;")
        main_layout.addWidget(title)

        # Scan Button
        scan_button = QPushButton("Scan System")
        scan_button.setFont(QFont('Arial', 16, QFont.Bold))
        scan_button.clicked.connect(self.run_scan)
        scan_button.setMinimumHeight(50)  # Increase button height for better UX
        main_layout.addWidget(scan_button)

        # scan softwares
        scan_button = QPushButton("Scan Softwares")
        scan_button.setFont(QFont('Arial', 16, QFont.Bold))
        scan_button.clicked.connect(self.run_scan_softwares)
        scan_button.setMinimumHeight(50)  # Increase button height for better UX
        main_layout.addWidget(scan_button)

        # scan ports
        scan_button = QPushButton("Scan open ports")
        scan_button.setFont(QFont('Arial', 16, QFont.Bold))
        scan_button.clicked.connect(self.run_scan_ports)
        scan_button.setMinimumHeight(50)  # Increase button height for better UX
        main_layout.addWidget(scan_button)

        # Progress Bar
        self.progress = QProgressBar(self)
        self.progress.setValue(0)
        self.progress.setFormat("Scan Progress: %p%")  # Show percentage with label
        self.progress.setMinimumHeight(30)
        main_layout.addWidget(self.progress)

        # Scroll Area for displaying scan results
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_widget = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_widget.setLayout(self.scroll_layout)
        self.scroll_area.setWidget(self.scroll_widget)
        main_layout.addWidget(self.scroll_area)

        # Stretch to adjust content position dynamically
        main_layout.addStretch(1)

        self.setLayout(main_layout)

    def clear_scroll_area(self):
        """Clears all widgets from the scroll area."""
        for i in reversed(range(self.scroll_layout.count())):
            widget_to_remove = self.scroll_layout.itemAt(i).widget()
            if widget_to_remove is not None:
                widget_to_remove.setParent(None)

    def run_scan(self):
        self.clear_scroll_area()
        self.progress.setValue(0)

        try:
            system_info = get_system_info()
            self.progress.setValue(20)

            software_versions = check_software()
            self.progress.setValue(40)

            antivirus = check_antivirus()
            installed_software_list = check_software_versions()
            self.progress.setValue(60)

            open_ports = scan_ports()
            open_ports_2 = scan_ports_2()
            self.progress.setValue(80)

            # Displaying scan results
            if isinstance(installed_software_list, list):
                recommendations = check_vulnerabilities(installed_software_list, 'vulnerabilities.json')
                self.progress.setValue(90)

                system_info_label = QLabel(
                    f"Open Ports Found in the device:{open_ports}\n"
                    f"\n"
                    f"Antivirus: {antivirus}\n"
                    f"\n"
                    f"System: {system_info['OS']}\n"
                    f"\n"f"\n"f"\n"
                    f"Software Version: {software_versions}\n"


                                           )
                self.scroll_layout.addWidget(system_info_label)

                for rec in recommendations:
                    software_info = QLabel(f"Software: {rec['software']} v{rec['version']}\n")
                    self.scroll_layout.addWidget(software_info)

                    vulnerability_text = ""
                    for vuln in rec['vulnerabilities']:
                        vulnerability_text += f"  - CVE: {vuln['cve_id']}\n    Severity: {vuln['severity']}\n    Description: {vuln['description']}\n    CVSS Score: {vuln['cvss_score']}\n\n"

                    vulnerability_text_edit = QTextEdit()
                    vulnerability_text_edit.setReadOnly(True)
                    vulnerability_text_edit.setText(vulnerability_text)
                    self.scroll_layout.addWidget(vulnerability_text_edit)

                    update_button = QPushButton(f"Update {rec['software']}")
                    update_button.clicked.connect(partial(self.run_update, rec['software']))
                    self.scroll_layout.addWidget(update_button)

                    separator = QFrame()
                    separator.setFrameShape(QFrame.HLine)
                    separator.setFrameShadow(QFrame.Sunken)
                    self.scroll_layout.addWidget(separator)

            else:
                error_label = QLabel("Error retrieving software information.")
                self.scroll_layout.addWidget(error_label)

        except Exception as e:
            error_label = QLabel(f"Error occurred: {e}")
            self.scroll_layout.addWidget(error_label)

        finally:
            self.progress.setValue(100)

    def run_scan_ports(self):
        global open_ports_label
        self.clear_scroll_area()
        self.progress.setValue(10)

        try:
            open_ports = scan_ports()
            self.progress.setValue(30)
            open_ports_2 = scan_ports_2()
            self.progress.setValue(50)

            # Convert ports to strings if they are integers
            open_ports_str = [str(port) for port in open_ports] if isinstance(open_ports, list) else []
            open_ports_2_str = [str(port) for port in open_ports_2] if isinstance(open_ports_2, list) else []

            open_ports_label = QLabel(
                f"Open Ports Found in the device:\n"
                f"{'\n'.join(open_ports_str) if open_ports_str else 'No open ports found.'}\n\n"
                f"Additional Scan Results:\n"
                f"{'\n'.join(open_ports_2_str) if open_ports_2_str else 'No additional open ports found.'}"
            )

            self.scroll_layout.addWidget(open_ports_label)
            self.progress.setValue(100)

        except Exception as e:
            error_label = QLabel(f"Error occurred while scanning ports: {e}")
            self.scroll_layout.addWidget(error_label)
            self.progress.setValue(100)

    def run_scan_softwares(self):
        self.clear_scroll_area()
        self.progress.setValue(0)

        try:
            self.progress.setValue(10)
            system_info = get_system_info()
            software_versions = check_software()
            self.progress.setValue(20)
            installed_software_info = check_software_versions()
            installed_software_list = check_software_versions()
            self.progress.setValue(50)

            # Debugging output
            print("Installed Software Info:", installed_software_info)  # You can log this or use a logger instead

            if isinstance(installed_software_list, list):
                recommendations = check_vulnerabilities(installed_software_list, 'vulnerabilities.json')
                self.progress.setValue(90)

                system_info_label = QLabel(
                    f"System: {system_info['OS']}\n"
                    f"\n"f"\n"f"\n"
                    f"Software Version: {software_versions}\n"

                )
                self.scroll_layout.addWidget(system_info_label)

                for rec in recommendations:
                    software_info = QLabel(f"Software: {rec['software']} v{rec['version']}\n")
                    self.scroll_layout.addWidget(software_info)

                    vulnerability_text = ""
                    for vuln in rec['vulnerabilities']:
                        vulnerability_text += f"  - CVE: {vuln['cve_id']}\n    Severity: {vuln['severity']}\n    Description: {vuln['description']}\n    CVSS Score: {vuln['cvss_score']}\n\n"

                    vulnerability_text_edit = QTextEdit()
                    vulnerability_text_edit.setReadOnly(True)
                    vulnerability_text_edit.setText(vulnerability_text)
                    self.scroll_layout.addWidget(vulnerability_text_edit)

                    update_button = QPushButton(f"Update {rec['software']}")
                    update_button.clicked.connect(partial(self.run_update, rec['software']))
                    self.scroll_layout.addWidget(update_button)

                    separator = QFrame()
                    separator.setFrameShape(QFrame.HLine)
                    separator.setFrameShadow(QFrame.Sunken)
                    self.scroll_layout.addWidget(separator)

            else:
                error_label = QLabel("Error retrieving software information.")
                self.scroll_layout.addWidget(error_label)

        except Exception as e:
            error_label = QLabel(f"Error occurred: {e}")
            self.scroll_layout.addWidget(error_label)

        finally:
            self.progress.setValue(100)


    def run_update(self, software_name):
        if software_name.lower() in ["python"]:
            self.update_worker = UpdateWorker(software_name)
            self.update_worker.update_complete.connect(self.on_update_complete)
            self.update_worker.start()
        else:
            QMessageBox.warning(self, "Update Not Supported",
                                f"No update method available for {software_name}. Please update manually.")

    def on_update_complete(self, message, version):
        QMessageBox.information(self, "Update Status", f"{message}\nUpdated Version: {version}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntiMalwareApp()
    window.show()
    sys.exit(app.exec_())
