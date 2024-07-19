import sys
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')  # Adjust this path based on your version of FMOS.

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import csv
import requests
import logging
from datetime import datetime, timedelta
from io import StringIO

# Configuration
firemon_host = 'https://localhost'
username = 'firemon'
password = 'firemon'
device_group_id = 1
control_id = 'eca59354-4bdb-4754-acb2-eeffb756860d'
csv_file_path = 'juniper_vulnerabilities.csv'
eol_csv_file_path = 'juniper_eol.csv'
log_file_path = 'firemon_juniper_version.log'
ignore_certificate = True
enable_logging = True  # Set to False to disable logging
logging_level = logging.DEBUG  # Set the desired logging level

# Email configuration
enable_email_alert = True
include_csv_attachment = True
email_sender = 'JuniperVuls@firemon.com'
email_recipient = 'adam.gunderson@firemon.com'
email_server = 'localhost'
email_port = 25
email_username = ''
email_password = ''
email_subject = 'Vulnerable Juniper Devices Report'
use_smtp_auth = False

# Alert options
output_to_console = True
output_to_csv = True  # Set to False to disable saving CSV locally

# EOL notification configuration
eol_notification_months = 6  # Notify if device will be EOL within this many months

# Set up logging
if enable_logging:
    logging.basicConfig(filename=log_file_path, level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')

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
    page_size = 10

    while True:
        url = f'{firemon_host}/securitymanager/api/domain/1/devicegroup/{device_group_id}/device?page={page}&pageSize={page_size}'
        headers = {'X-FM-AUTH-TOKEN': token}
        try:
            response = requests.get(url, headers=headers, verify=not ignore_certificate)
            if enable_logging:
                logging.debug(f'Response status code: {response.status_code}')
                logging.debug(f'Response text: {response.text}')
            response.raise_for_status()
            data = response.json()
            devices.extend(data.get('results', []))
            if enable_logging:
                logging.info(f'Page {page} retrieved with {len(data.get("results", []))} devices')
            if len(data.get('results', [])) < page_size:
                break
            page += 1
        except requests.exceptions.RequestException as e:
            if enable_logging:
                logging.error(f'Error retrieving devices: {e}')
            raise

    if enable_logging:
        logging.info(f'Total devices retrieved: {len(devices)}')
    return devices

# Function to retrieve the software version of a specific device
def get_device_version(token, device_id):
    url = f'{firemon_host}/securitymanager/api/domain/1/control/{control_id}/execute/device/{device_id}?allControlResults=true&includeResultDetails=false'
    headers = {'X-FM-AUTH-TOKEN': token}
    try:
        response = requests.get(url, headers=headers, verify=not ignore_certificate)
        response.raise_for_status()
        data = response.json()
        if enable_logging:
            logging.debug(f'Control API response for device ID {device_id}: {response.text}')
        regex_matches = data.get('regexMatches', [])
        if regex_matches:
            version_line = regex_matches[0].get('line', '')
            version = version_line.strip().split('<version>')[1].split('</version>')[0]
            if enable_logging:
                logging.info(f'Device ID {device_id} version retrieved: {version}')
            return version
        if enable_logging:
            logging.info(f'Device ID {device_id} version not found')
        return None
    except requests.exceptions.RequestException as e:
        if enable_logging:
            logging.error(f'Error retrieving version for device ID {device_id}: {e}')
        return None

# Function to parse vulnerabilities from a CSV file
def parse_vulnerabilities(csv_file_path):
    vulnerabilities = {}
    try:
        with open(csv_file_path, mode='r') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            for row in reader:
                if len(row) < 2:
                    continue
                version, cve = row[:2]
                vulnerabilities.setdefault(version, []).append(cve)
        if enable_logging:
            logging.info(f'Parsed vulnerabilities: {vulnerabilities}')
    except Exception as e:
        if enable_logging:
            logging.error(f'Error parsing vulnerabilities: {e}')
        raise
    return vulnerabilities

# Function to parse EOL data from a CSV file
def parse_eol_data(csv_file_path):
    eol_data = {}
    try:
        with open(csv_file_path, mode='r') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            for row in reader:
                if len(row) < 4:
                    continue
                product, _, _, eol_date_str, _ = row[:5]
                eol_date = datetime.strptime(eol_date_str, '%m/%d/%Y')
                eol_data[product] = eol_date
        if enable_logging:
            logging.info(f'Parsed EOL data: {eol_data}')
    except Exception as e:
        if enable_logging:
            logging.error(f'Error parsing EOL data: {e}')
        raise
    return eol_data

# Function to parse the version parts correctly, including handling non-numeric parts
def parse_version(version):
    try:
        parts = version.replace('X', '.').replace('r', '.').replace('S', '.').replace('D', '.').split('.')
        main_version_parts = []
        r_release_num = 0
        s_release = 0
        evo = False

        for part in parts:
            if part.isdigit():
                main_version_parts.append(int(part))
            elif part.isalnum():
                if part.startswith('EVO'):
                    evo = True
                elif part.isdigit():
                    r_release_num = int(part)
                elif part.replace('S', '').isdigit():
                    s_release = int(part.replace('S', ''))
                elif part.replace('D', '').isdigit():
                    s_release = int(part.replace('D', ''))

        if not main_version_parts:
            logging.error(f'Invalid version format: {version}')
            return None

        return main_version_parts, r_release_num, s_release, evo

    except ValueError as e:
        logging.error(f'Invalid version format: {version}')
        return None

# Function to compare device versions against vulnerability versions
def compare_versions(device_version, vulnerability_version):
    device_parts = parse_version(device_version)
    vuln_parts = parse_version(vulnerability_version)

    if not device_parts or not vuln_parts:
        return False

    for dv, vv in zip(device_parts[0], vuln_parts[0]):
        if dv < vv:
            return True
        elif dv > vv:
            return False

    if device_parts[1] < vuln_parts[1]:
        return True
    elif device_parts[1] > vuln_parts[1]:
        return False

    if device_parts[2] < vuln_parts[2]:
        return True
    elif device_parts[2] > vuln_parts[2]:
        return False

    if device_parts[3] and not vuln_parts[3]:
        return False
    elif not device_parts[3] and vuln_parts[3]:
        return True

    return False

# Function to check if a device version is near EOL
def is_near_eol(device_version, eol_data, notification_months):
    if device_version not in eol_data:
        return False, None
    eol_date = eol_data[device_version]
    notification_date = datetime.now() + timedelta(days=notification_months*30)
    return eol_date <= notification_date, eol_date

# Function to send email alert
def send_email_alert(vulnerable_devices, eol_devices, csv_data=None):
    try:
        msg = MIMEMultipart()
        msg['From'] = email_sender
        msg['To'] = email_recipient
        msg['Subject'] = email_subject

        body = "The following devices have vulnerabilities:\n\n"
        for device in vulnerable_devices:
            body += f"Name: {device['name']}, ID: {device['id']}, Type: {device['devicePack']['deviceName']}, IP: {device.get('managementIp', 'N/A')}, Version: {device['version']}, CVEs: {', '.join(device['cves'])}\n"
        
        if eol_devices:
            body += "\nThe following devices are near EOL:\n\n"
            for device in eol_devices:
                body += f"Name: {device['name']}, ID: {device['id']}, Type: {device['devicePack']['deviceName']}, IP: {device.get('managementIp', 'N/A')}, Version: {device['version']}, EOL Date: {device['eol_date'].strftime('%m/%d/%Y')}\n"

        msg.attach(MIMEText(body, 'plain'))

        if include_csv_attachment and csv_data:
            # Attach CSV file
            csv_attachment = MIMEApplication(csv_data.getvalue())
            csv_attachment.add_header('Content-Disposition', 'attachment', filename='vulnerable_devices.csv')
            msg.attach(csv_attachment)

        server = smtplib.SMTP(email_server, email_port)
        server.starttls()
        if use_smtp_auth:
            server.login(email_username, email_password)
        text = msg.as_string()
        server.sendmail(email_sender, email_recipient, text)
        server.quit()

        if enable_logging:
            logging.info(f'Email alert sent to {email_recipient}')
    except Exception as e:
        if enable_logging:
            logging.error(f'Error sending email: {e}')
        raise

# Function to check vulnerabilities for devices from a specific vendor
def check_vulnerabilities(token, devices, vulnerabilities, eol_data):
    vulnerable_devices = []
    eol_devices = []
    device_cve_map = {}
    csv_data = StringIO() if include_csv_attachment and not output_to_csv else None
    csv_writer = csv.writer(csv_data) if csv_data else None

    if csv_writer:
        csv_writer.writerow(['Name', 'ID', 'Type', 'IP', 'Version', 'CVEs'])

    for device in devices:
        if device.get('devicePack', {}).get('groupId') == 'com.fm.sm.dp.juniper_space':
            if enable_logging:
                logging.info(f'Skipping device {device["id"]} ({device["name"]}) with devicePackGroupId com.fm.sm.dp.juniper_space')
            continue

        device_id = device['id']
        device_name = device['name']
        device_type = device['devicePack']['deviceName']
        device_ip = device.get('managementIp', 'N/A')
        device_version = get_device_version(token, device_id)

        if device_version:
            if enable_logging:
                logging.info(f'Checking device {device_name} (ID: {device_id}) with version {device_version}')
            for vuln_version, cves in vulnerabilities.items():
                if compare_versions(device_version, vuln_version):
                    if enable_logging:
                        logging.warning(f'Device {device_name} (ID: {device_id}) with version {device_version} is vulnerable to {", ".join(cves)}')
                    if device_id not in device_cve_map:
                        device_cve_map[device_id] = {
                            'name': device_name,
                            'id': device_id,
                            'devicePack': device['devicePack'],
                            'managementIp': device_ip,
                            'version': device_version,
                            'cves': set()
                        }
                    device_cve_map[device_id]['cves'].update(cves)

            near_eol, eol_date = is_near_eol(device_version, eol_data, eol_notification_months)
            if near_eol:
                eol_devices.append({
                    'name': device_name,
                    'id': device_id,
                    'devicePack': device['devicePack'],
                    'managementIp': device_ip,
                    'version': device_version,
                    'eol_date': eol_date
                })

    for device in device_cve_map.values():
        device['cves'] = list(device['cves'])
        vulnerable_devices.append(device)
        if csv_writer:
            csv_writer.writerow([device['name'], device['id'], device['devicePack']['deviceName'], device.get('managementIp', 'N/A'), device['version'], ', '.join(device['cves'])])

    if output_to_console:
        for device in vulnerable_devices:
            print(f"Name: {device['name']}, ID: {device['id']}, Type: {device['devicePack']['deviceName']}, IP: {device.get('managementIp', 'N/A')}, Version: {device['version']}, CVEs: {', '.join(device['cves'])}")

    if output_to_csv:
        try:
            with open(csv_file_path, mode='w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Name', 'ID', 'Type', 'IP', 'Version', 'CVEs'])
                for device in vulnerable_devices:
                    writer.writerow([device['name'], device['id'], device['devicePack']['deviceName'], device.get('managementIp', 'N/A'), device['version'], ', '.join(device['cves'])])
            if enable_logging:
                logging.info(f'Vulnerable devices saved to {csv_file_path}')
        except Exception as e:
            if enable_logging:
                logging.error(f'Error writing to CSV file: {e}')
            raise

    if enable_email_alert:
        send_email_alert(vulnerable_devices, eol_devices, csv_data=csv_data)

# Main function to orchestrate the script's execution
def main():
    token = authenticate()
    try:
        devices = get_devices(token)
        vulnerabilities = parse_vulnerabilities(csv_file_path)
        eol_data = parse_eol_data(eol_csv_file_path)
        check_vulnerabilities(token, devices, vulnerabilities, eol_data)
    except requests.exceptions.HTTPError as e:
        if enable_logging:
            logging.error(f'HTTP error occurred: {e}')
    except Exception as e:
        if enable_logging:
            logging.error(f'An error occurred: {e}')

if __name__ == '__main__':
    main()
