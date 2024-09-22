
import subprocess
import sys
from wsgiref.simple_server import software_version

import psutil
import platform
import json
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QProgressBar, QTextEdit, QScrollArea
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QTimer




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
def check_software():
    try:
        installed_software = subprocess.check_output("wmic product get name,version", shell=True, encoding='utf-8', errors='replace')
        return  installed_software
    except Exception as e:
        return f"Error: {e}"



def check_antivirus():
    # Check if antivirus is running
    if "antivirus" not in (p.name().lower() for p in psutil.process_iter()):
        return f"Warning: No active antivirus detected. It is recommended to install one."
    else:
        return f"Antivirus detected and running."
# Function to load vulnerabilities from a static JSON file with correct encoding
def load_vulnerabilities_from_file(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        return f"Error loading vulnerabilities from file: {e}"


# Function to analyze vulnerabilities and return the most severe ones
def analyze_vulnerabilities(software, vulnerabilities):
    software_vulnerabilities = []

    for vulnerability in vulnerabilities['CVE_Items']:
        cve_id = vulnerability['cve']['CVE_data_meta']['ID']
        description = vulnerability['cve']['description']['description_data'][0]['value']

        # Try to get CVSSv2 or CVSSv3 score, and handle cases where they are missing
        cvss_score = None
        severity = "Low"

        if 'impact' in vulnerability:
            if 'baseMetricV2' in vulnerability['impact']:
                cvss_score = vulnerability['impact']['baseMetricV2']['cvssV2']['baseScore']
            elif 'baseMetricV3' in vulnerability['impact']:
                cvss_score = vulnerability['impact']['baseMetricV3']['cvssV3']['baseScore']

        if cvss_score is None:
            cvss_score = 0.0  # Default value for vulnerabilities with no CVSS score

        # Convert the CVSS score to severity level
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

    # Sort vulnerabilities by severity (most critical first)
    software_vulnerabilities = sorted(software_vulnerabilities, key=lambda x: x['cvss_score'], reverse=True)
    return software_vulnerabilities[:3]


# Function to get installed software on Windows using subprocess
def check_software_versions():
    try:
        installed_software = subprocess.check_output("wmic product get name,version", shell=True, encoding='utf-8', errors='replace')
        software_list = []
        lines = installed_software.splitlines()
        for line in lines[1:]:
            if line.strip():
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    version = parts[1].strip()
                    software_list.append({"name": name, "version": version})
        return software_list
    except Exception as e:
        return f"Error: {e}"


# Function to check vulnerabilities and return only the most affected software with top vulnerabilities
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

        # Sort the software by the severity of its most severe vulnerability
        sorted_software = sorted(software_vulnerabilities, key=lambda x: x['vulnerabilities'][0]['cvss_score'], reverse=True)
        return sorted_software[:15]
    else:
        return []


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
        self.result_area.clear()  # Clear any previous output
        self.progress.setValue(0)

        try:
            # Gather system information and installed software
            system_info = get_system_info()
            software_versions = check_software()
            antivirus = check_antivirus()
            installed_software_list = check_software_versions()

            if isinstance(installed_software_list, list):
                # Load vulnerabilities and perform scan
                self.progress.setValue(20)
                recommendations = check_vulnerabilities(installed_software_list, 'vulnerabilities.json')

                # Ensure progress reflects work done
                self.progress.setValue(80)

                # Initialize result text and add system info once
                result_text = (
                    f"System: {system_info['OS']} (Version: {system_info['Version']})\n"
                    f"Processor: {system_info['Processor']}\n"
                    f"Antivirus Status: {antivirus}\n\n"
                    f"Software Version: {software_versions}\n"
                    "Top Vulnerabilities:\n\n"
                )

                # Loop through recommendations and append only necessary info
                if recommendations:
                    for rec in recommendations:
                        result_text += f"Software: {rec['software']} (Version: {rec['version']})\n"
                        for vuln in rec['vulnerabilities']:
                            result_text += (
                                f"  - CVE: {vuln['cve_id']}\n"
                                f"    Severity: {vuln['severity']}\n"
                                f"    Description: {vuln['description']}\n"
                                f"    CVSS Score: {vuln['cvss_score']}\n\n"
                            )
                        result_text += f"Recommendation: Update {rec['software']} to the latest version or apply security patches.\n\n"
                else:
                    result_text += "No vulnerabilities found for the installed software.\n"

                # Set the result area to the final result text
                self.result_area.setPlainText(result_text)
            else:
                # Handle case where installed_software_list is an error message
                self.result_area.setPlainText(installed_software_list)

        except Exception as e:
            # Display any errors that occur during the scan
            self.result_area.setPlainText(f"Error occurred: {e}")

        finally:
            # Ensure the progress bar reaches 100% after scan completion
            self.progress.setValue(100)


# Application loop
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntiMalwareApp()
    window.show()
    sys.exit(app.exec_())
