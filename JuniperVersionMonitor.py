import sys
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')  # Adjust this path based on your version of FMOS.
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import csv
import requests
import logging
import os
import json
import yaml
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from io import StringIO
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Load Configuration from config.yaml
with open('config.yaml', 'r') as config_file:
    config = yaml.safe_load(config_file)

# Set Configuration Variables
firemon_host = config["firemon_host"]
username = config["username"]
password = config["password"]
device_group_id = config["device_group_id"]
control_id = config["control_id"]
cpe_data_path = config["cpe_data_path"]
eol_csv_file_path = config["eol_csv_file_path"]
ignore_certificate = config["ignore_certificate"]
cvss_threshold = config["cvss_threshold"]

eol_notification_months = config["eol_notification_months"]

enable_email_alert = config["enable_email_alert"]
output_to_console = config["output_to_console"]
output_to_csv = config["output_to_csv"]
output_csv_path = config["output_csv_path"]
cve_csv_path = config["cve_csv_path"]

enable_logging = config["enable_logging"]
log_file_path = config["log_file_path"]
logging_level = getattr(logging, config["logging_level"])
max_log_size = config["max_log_size"]
backup_log_count = config["backup_log_count"]

include_csv_attachment = config["include_csv_attachment"]
email_sender = config["email_sender"]
email_recipient = config["email_recipient"]
email_server = config["email_server"]
email_port = config["email_port"]
email_username = config["email_username"]
email_password = config["email_password"]
email_subject = config["email_subject"]
use_smtp_auth = config["use_smtp_auth"]

max_workers = config["max_workers"]

# Set up logging
if enable_logging:
    handler = RotatingFileHandler(
        log_file_path, 
        maxBytes=max_log_size, 
        backupCount=backup_log_count
    )
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging_level)
    root_logger.addHandler(handler)

    # Add a StreamHandler for console output if needed
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

# Disable warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to authenticate to FireMon and get an authentication token
def authenticate():
    url = f'{firemon_host}/securitymanager/api/authentication/login'
    payload = {'username': username, 'password': password}
    try:
        response = requests.post(url, json=payload, verify=not ignore_certificate)
        response.raise_for_status()
        if enable_logging:
            logging.info('Successfully authenticated to FireMon')
        return response.json()['token']
    except requests.exceptions.RequestException as e:
        if enable_logging:
            logging.error(f'Error during authentication: {e}')
        raise

# Function to retrieve devices from a specified device group, handling pagination
def get_devices(token):
    devices = []
    page = 0
    page_size = 50  # Increase page size for fewer requests

    while True:
        url = f'{firemon_host}/securitymanager/api/domain/1/devicegroup/{device_group_id}/device?page={page}&pageSize={page_size}'
        headers = {'X-FM-AUTH-TOKEN': token}
        try:
            response = requests.get(url, headers=headers, verify=not ignore_certificate)
            response.raise_for_status()
            data = response.json()
            devices.extend(data.get('results', []))
            if enable_logging:
                logging.debug(f'API Response: {data}')
                for device in data.get('results', []):
                    logging.debug(f'Retrieved device: {device}')
            if len(data.get('results', [])) < page_size:
                break
            page += 1
        except requests.exceptions.RequestException as e:
            if enable_logging:
                logging.error(f'Error retrieving devices: {e}')
            raise

    if enable_logging:
        logging.info(f'Total devices in device group: {len(devices)}')
    return devices

# Function to retrieve the software version of a specific device
def get_device_version(token, device_id):
    url = f'{firemon_host}/securitymanager/api/domain/1/control/{control_id}/execute/device/{device_id}?allControlResults=true&includeResultDetails=false'
    headers = {'X-FM-AUTH-TOKEN': token}
    try:
        response = requests.get(url, headers=headers, verify=not ignore_certificate)
        response.raise_for_status()
        data = response.json()
        logging.debug(f'API Response for device {device_id}: {data}')
        regex_matches = data.get('regexMatches', [])
        if regex_matches:
            version_line = regex_matches[0].get('line', '')
            logging.debug(f'Version line for device {device_id}: {version_line}')
            match = re.search(r'junos="http://xml.juniper.net/junos/([^/]+)(?:-EVO)?/junos"', version_line)
            if match:
                version = match.group(1)
                logging.debug(f'Parsed version for device {device_id}: {version}')
                return version
        return None
    except requests.exceptions.RequestException as e:
        if enable_logging:
            logging.error(f'Error retrieving version for device ID {device_id}: {e}')
        return None

# Function to parse vulnerabilities from a JSON file
def parse_cpe_data(json_file_path):
    cpe_data = []
    if not os.path.exists(json_file_path):
        logging.warning(f'CPE JSON file not found: {json_file_path}')
        return cpe_data
    try:
        with open(json_file_path, 'r') as jsonfile:
            cpe_data = json.load(jsonfile)
        logging.debug(f'Parsed CPE data: {cpe_data}')  # Changed from INFO to DEBUG
        logging.info(f'Successfully parsed {len(cpe_data)} CPE entries from {json_file_path}')
    except Exception as e:
        logging.error(f'Error parsing CPE data: {e}')
        raise
    return cpe_data

# Function for checking if a device's version is approaching or past its End of Life (EOL) date.
def check_eol_status(device_version, eol_data):
    for version, eol_date in eol_data.items():
        if match_versions(device_version, version):
            return eol_date
    return None

# Function to parse EOL data from a CSV file
def parse_eol_data(csv_file_path):
    eol_data = {}
    if not os.path.exists(csv_file_path):
        logging.warning(f'EOL CSV file not found: {csv_file_path}')
        return None
    try:
        with open(csv_file_path, mode='r') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            for row in reader:
                if len(row) < 4 or not row[3]:
                    continue
                product, _, _, eol_date_str, _ = row[:5]
                try:
                    eol_date = datetime.strptime(eol_date_str, '%m/%d/%Y')
                    eol_data[product] = eol_date
                except ValueError:
                    if enable_logging:
                        logging.warning(f'Skipping invalid date format for product: {product}, EOL Date: {eol_date_str}')
        if enable_logging:
            logging.info(f'Parsed EOL data: {eol_data}')
    except Exception as e:
        if enable_logging:
            logging.error(f'Error parsing EOL data: {e}')
        return None

    return eol_data

# Function to parse the version parts correctly, including handling non-numeric parts
def parse_version(version):
    # Split version into main parts and potential service pack
    main_parts = version.split('-')[0]
    service_pack = version.split('-')[1] if '-' in version else ''

    # Parse main version parts
    parts = main_parts.replace('R', '.').split('.')
    parsed = [int(p) if p.isdigit() else p for p in parts]

    # Parse service pack if present
    if service_pack:
        sp_parts = service_pack.replace('S', '.').split('.')
        parsed.extend([int(p) if p.isdigit() else p for p in sp_parts])

    return parsed

def match_versions(device_version, cpe_version):
    device_parts = parse_version(device_version.replace("-EVO", ""))
    cpe_parts = parse_version(cpe_version)

    # Compare each part of the version
    for dev_part, cpe_part in zip(device_parts, cpe_parts):
        if cpe_part == '*':
            continue
        if dev_part != cpe_part:
            return False

    # If CPE version is shorter, it's a match (e.g., 23.2 matches 23.2R1)
    return len(cpe_parts) <= len(device_parts)

# Function to check if a device is vulnerable based on CPE data and collect detailed information
def check_vulnerabilities(device_version, cpe_data, device_name, device_ip, cvss_threshold):
    vulnerabilities = []
    is_evolved = "-EVO" in device_version
    device_version_without_evo = device_version.replace("-EVO", "")

    for entry in cpe_data:
        try:
            if entry['cvss_score'] != 'N/A' and float(entry['cvss_score']) < cvss_threshold:
                continue
        except ValueError:
            # If CVSS score is 'N/A' or not a valid float, we'll include it
            pass

        cpe = entry['cpe']
        cpe_parts = cpe.split(':')
        cpe_version = cpe_parts[5]

        # Check if the CPE is for the correct Junos variant (Evolved or standard)
        if is_evolved and not cpe.startswith("cpe:2.3:o:juniper:junos_os_evolved"):
            continue
        if not is_evolved and not cpe.startswith("cpe:2.3:o:juniper:junos"):
            continue

        logging.debug(f"Matching device version {device_version_without_evo} against CPE version {cpe_version}")
        if match_versions(device_version_without_evo, cpe_version):
            logging.debug(f"Matched CPE {cpe} for device {device_name} with version {device_version}")
            vulnerability_info = {
                'Device Name': device_name,
                'Device IP': device_ip,
                'cve': entry['cve'],
                'description': entry['description'],
                'severity': entry['severity'],
                'cvss_score': entry['cvss_score'],
                'attackVector': entry['attackVector'],
                'attackComplexity': entry['attackComplexity'],
                'availabilityImpact': entry['availabilityImpact'],
                'exploitabilityScore': entry['exploitabilityScore'],
                'impactScore': entry['impactScore'],
                'vendorAdvisory': entry['vendorAdvisory']
            }
            vulnerabilities.append(vulnerability_info)

    return vulnerabilities

# Function to process each device
def process_device(token, device, cpe_data, eol_data, cvss_threshold):
    vendor = device.get('devicePack', {}).get('vendor', '')
    artifact_id = device.get('devicePack', {}).get('artifactId', '')
    management_ip = device.get('managementIp', 'N/A')
    is_juniper = vendor == 'Juniper Networks' and artifact_id in ['juniper_ex', 'juniper_mseries', 'juniper_srx', 'juniper_qfx']
    
    if is_juniper:
        device_id = device.get('id', '')
        device_name = device.get('name', '')
        device_version = get_device_version(token, device_id)
        if device_version:
            logging.debug(f"Processing device {device_name} with version {device_version}")
            is_evolved = "-EVO" in device_version
            logging.debug(f"Is Evolved: {is_evolved}")
            result = {
                'Device ID': device_id,
                'Device Name': device_name,
                'Device Version': device_version,
                'Management IP': management_ip
            }
            has_findings = False

            if cpe_data:
                cves = check_vulnerabilities(device_version, cpe_data, device_name, management_ip, cvss_threshold)
                if cves:
                    result['Vulnerabilities'] = ', '.join(set([cve['cve'] for cve in cves]))
                    has_findings = True

            if eol_data:
                eol_date = check_eol_status(device_version, eol_data)
                if eol_date and eol_date <= datetime.now() + timedelta(days=eol_notification_months * 30):
                    result['EOL Date'] = eol_date.strftime('%Y-%m-%d')
                    has_findings = True

            if has_findings:
                result['Junos OS Type'] = 'Junos OS Evolved' if '-EVO' in device_version else 'Junos'
                return result, is_juniper, cves if cves else []
        return None, is_juniper, []
    return None, is_juniper, []

# Function to send an email with the results
def send_email(subject, body, attachments=None):
    try:
        msg = MIMEMultipart()
        msg['From'] = email_sender
        msg['To'] = email_recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        if attachments:
            for attachment_path in attachments:
                with open(attachment_path, 'rb') as attachment:
                    part = MIMEApplication(attachment.read(), Name=os.path.basename(attachment_path))
                    part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                    msg.attach(part)

        server = smtplib.SMTP(email_server, email_port)
        if use_smtp_auth:
            server.login(email_username, email_password)
        server.send_message(msg)
        server.quit()

        if enable_logging:
            logging.info('Email sent successfully')
    except Exception as e:
        if enable_logging:
            logging.error(f'Error sending email: {e}')

# Main function
def main():
    start_time = datetime.now()
    try:
        token = authenticate()
        devices = get_devices(token)

        cpe_data = []
        if os.path.exists(cpe_data_path):
            cpe_data = parse_cpe_data(cpe_data_path)

        eol_data = parse_eol_data(eol_csv_file_path) if os.path.exists(eol_csv_file_path) else None

        if not cpe_data and not eol_data:
            print("No CVE/CPE or EOL data available. Nothing to do.")
            if enable_logging:
                logging.info("No CVE/CPE or EOL data available. Nothing to do.")
            return

        findings = []
        total_vulnerable_devices = set()
        total_eol_devices = 0
        total_juniper_devices_checked = 0
        total_juniper_devices = 0
        total_devices = len(devices)
        cve_details = defaultdict(set)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_device, token, device, cpe_data, eol_data, cvss_threshold) for device in devices]

            for future in as_completed(futures):
                result, is_juniper, cves = future.result()
                if is_juniper:
                    total_juniper_devices += 1
                    total_juniper_devices_checked += 1
                    if result:
                        findings.append(result)
                        if 'Vulnerabilities' in result:
                            total_vulnerable_devices.add(result['Device ID'])
                        if 'EOL Date' in result:
                            total_eol_devices += 1
                        for cve in cves:
                            cve_key = (cve['cve'], cve['description'], cve['severity'], cve['cvss_score'], cve['attackVector'], cve['attackComplexity'], cve['availabilityImpact'], cve['exploitabilityScore'], cve['impactScore'], cve['vendorAdvisory'])
                            device_info = f"{result['Device Name']} ({result['Management IP']})"
                            cve_details[cve_key].add(device_info)

        if findings:
            end_time = datetime.now()
            run_duration = (end_time - start_time).total_seconds()
            if output_to_console:
                for finding in findings:
                    print(finding)

            fieldnames = ['Device ID', 'Device Name', 'Device Version', 'Management IP', 'Vulnerabilities', 'Junos OS Type']
            if eol_data:
                fieldnames.insert(-1, 'EOL Date')

            if output_to_csv:
                with open(output_csv_path, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for finding in findings:
                        writer.writerow(finding)

                # Update the CVE details CSV
                cve_fieldnames = ['cve', 'description', 'severity', 'cvss_score', 'attackVector', 'attackComplexity', 'availabilityImpact', 'exploitabilityScore', 'impactScore', 'vendorAdvisory', 'Device Count', 'Affected Devices']
                with open(cve_csv_path, 'w', newline='') as cvefile:
                    writer = csv.DictWriter(cvefile, fieldnames=cve_fieldnames)
                    writer.writeheader()
                    for cve_key, devices in cve_details.items():
                        cve_data = {
                            'cve': cve_key[0],
                            'description': cve_key[1],
                            'severity': cve_key[2],
                            'cvss_score': cve_key[3],
                            'attackVector': cve_key[4],
                            'attackComplexity': cve_key[5],
                            'availabilityImpact': cve_key[6],
                            'exploitabilityScore': cve_key[7],
                            'impactScore': cve_key[8],
                            'vendorAdvisory': cve_key[9],
                            'Device Count': len(devices),
                            'Affected Devices': ', '.join(devices)
                        }
                        writer.writerow(cve_data)

            email_body = (
                f"Total devices in device group: {total_devices}\n"
                f"Total Juniper devices checked: {total_juniper_devices_checked}\n"
                f"Total devices with vulnerabilities: {len(total_vulnerable_devices)}\n"
            )
            if eol_data:
                email_body += f"Total devices with EOL versions: {total_eol_devices}\n"
            email_body += (
                f"Script start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Script end time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Script run duration: {round(run_duration)} seconds\n"
            )

            if output_to_console:
                print(email_body)

            if enable_email_alert:
                if include_csv_attachment:
                    email_body += "\nFindings attached."
                    attachments = [output_csv_path, cve_csv_path]
                else:
                    email_body += "\nFindings:\n"
                    for finding in findings:
                        email_body += "\n".join([f"{key}: {value}" for key, value in finding.items()]) + "\n\n"
                    attachments = None

                send_email(email_subject, email_body, attachments)

    except Exception as e:
        if enable_logging:
            logging.error(f'Unexpected error: {e}')
        raise

if __name__ == '__main__':
    main()
