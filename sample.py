import sys

from functools import partial
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QProgressBar, QTextEdit, QScrollArea, QFrame
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

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
            QLabel {
                color: #D8DEE9;
            }
        """)

        # Window setup
        self.setWindowTitle("Anti-Malware Security Suite")
        self.setGeometry(100, 100, 800, 600)

        main_layout = QVBoxLayout()

        # Title
        title = QLabel("Anti-Malware Software")
        title.setFont(QFont('Arial', 24))
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # Scan button
        scan_button = QPushButton("Scan System")
        scan_button.clicked.connect(self.run_scan)
        main_layout.addWidget(scan_button)

        # Progress bar
        self.progress = QProgressBar(self)
        main_layout.addWidget(self.progress)

        # Scroll Area setup
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_widget = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_area.setWidget(self.scroll_widget)
        main_layout.addWidget(self.scroll_area)

        self.setLayout(main_layout)

    def clear_scroll_area(self):
        # Clear the layout in the scroll area safely
        for i in reversed(range(self.scroll_layout.count())):
            widget_to_remove = self.scroll_layout.itemAt(i).widget()
            if widget_to_remove is not None:
                widget_to_remove.setParent(None)

    def run_scan(self):
        self.clear_scroll_area()  # Clear previous content
        self.progress.setValue(0)

        try:
            system_info = get_system_info()
            software_versions = check_software()
            antivirus = check_antivirus()
            installed_software_list = check_software_versions()

            if isinstance(installed_software_list, list):
                self.progress.setValue(20)
                recommendations = check_vulnerabilities(installed_software_list, 'vulnerabilities.json')
                self.progress.setValue(80)

                # Display system info
                system_info_label = QLabel(f"System: {system_info['OS']}\nSoftware Version: {software_versions}\nAntivirus: {antivirus}\n\n")
                self.scroll_layout.addWidget(system_info_label)

                # Display vulnerabilities and add buttons for each software
                for rec in recommendations:
                    software_info = QLabel(f"Software: {rec['software']} v{rec['version']}\n")
                    self.scroll_layout.addWidget(software_info)

                    for vuln in rec['vulnerabilities']:
                        vuln_info = QLabel(f"  - CVE: {vuln['cve_id']}\n    Severity: {vuln['severity']}\n    Description: {vuln['description']}\n    CVSS Score: {vuln['cvss_score']}\n")
                        self.scroll_layout.addWidget(vuln_info)

                    # Add the update button for this software
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

    # Function to simulate an update process for the software
    def run_update(self, software_name):
        try:
            # Simulate an update (replace with actual update logic if needed)
            update_status = f"Simulating update for {software_name}..."
            result_label = QLabel(update_status)
            self.scroll_layout.addWidget(result_label)
            result_label.show()
        except Exception as e:
            result_label = QLabel(f"Update failed for {software_name}: {str(e)}")
            self.scroll_layout.addWidget(result_label)
            result_label.show()

# Helper functions (simulated versions)
def get_system_info():
    return {
        "OS": "Windows 10",
        "Version": "21H2",
        "Architecture": "x86_64",
        "Processor": "Intel(R) Core(TM) i7"
    }

def check_software():
    return "Windows Defender Antivirus"

def check_antivirus():
    return "Windows Defender running."

def check_software_versions():
    return [{"name": "ExampleSoftware", "version": "1.0.0"}]

def check_vulnerabilities(installed_software, vuln_file):
    # Simulated data for vulnerabilities
    return [
        {
            "software": "ExampleSoftware",
            "version": "1.0.0",
            "vulnerabilities": [
                {"cve_id": "CVE-2024-1234", "description": "Sample vulnerability", "cvss_score": 9.8, "severity": "Critical"},
                {"cve_id": "CVE-2024-5678", "description": "Another vulnerability", "cvss_score": 7.2, "severity": "High"}
            ]
        }
    ]

# Application loop
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntiMalwareApp()
    window.show()
    sys.exit(app.exec_())
