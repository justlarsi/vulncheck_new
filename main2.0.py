import subprocess
from wsgiref.simple_server import software_version


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

software=check_software_versions()