import json
import subprocess

from PyQt5.QtWidgets import QApplication


# Function to load vulnerabilities from a static JSON file with correct encoding
def load_vulnerabilities_from_file(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading vulnerabilities from file: {e}")
        return None


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

        # Set a default value for CVSS score if it's missing
        if cvss_score is None:
            cvss_score = 0.0  # Default value for vulnerabilities with no CVSS score

        # Convert the CVSS score to severity level
        if cvss_score >= 9.0:
            severity = "Critical"
        elif cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"

        # Add vulnerability to the list for the software
        software_vulnerabilities.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity
        })

    # Sort vulnerabilities by seve rity (most critical first)
    software_vulnerabilities = sorted(software_vulnerabilities, key=lambda x: x['cvss_score'], reverse=True)

    # Limit to top 3 most severe vulnerabilities for each software
    return software_vulnerabilities[:3]


# Function to get installed software on Windows using subprocess
def check_software_versions():
    try:
        installed_software = subprocess.check_output("wmic product get name,version", shell=True, encoding='utf-8',
                                                     errors='replace')
        software_list = []
        # Process the output
        lines = installed_software.splitlines()
        for line in lines[1:]:  # Skip the header line
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

    if vulnerabilities:
        for software in installed_software:
            severe_vulnerabilities = analyze_vulnerabilities(software, vulnerabilities)
            if severe_vulnerabilities:
                software_vulnerabilities.append({
                    "software": software['name'],
                    "version": software['version'],
                    "vulnerabilities": severe_vulnerabilities
                })

        # Sort the software by the severity of its most severe vulnerability
        sorted_software = sorted(software_vulnerabilities, key=lambda x: x['vulnerabilities'][0]['cvss_score'],
                                 reverse=True)

        # Limit to the top 15 most affected software
        return sorted_software[:15]
    else:
        print("No vulnerabilities found.")
        return []


# Main script
vuln_file = 'vulnerabilities.json'  # Ensure this file contains the static JSON CVE data
installed_software_list = check_software_versions()

if isinstance(installed_software_list, list):
    recommendations = check_vulnerabilities(installed_software_list, vuln_file)

    # Output the most vulnerable software with a few vulnerabilities and recommendations
    for rec in recommendations:
        print(f"Software: {rec['software']} v{rec['version']}")
        print(f"Top Vulnerabilities:")

        for vuln in rec['vulnerabilities']:
            print(f"  - CVE: {vuln['cve_id']}")
            print(f"    Severity: {vuln['severity']}")
            print(f"    Description: {vuln['description']}")
            print(f"    CVSS Score: {vuln['cvss_score']}\n")

        print(f"Recommendation: Update {rec['software']} to the latest version or apply security patches.\n")
else:
    print(installed_software_list)  # Print error message if there's an issue


