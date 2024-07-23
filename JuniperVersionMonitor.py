import sys
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')  # Adjust this path based on your version of FMOS.
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import csv
import requests
import logging
from logging.handlers import RotatingFileHandler
import os
import json
from datetime import datetime, timedelta
from io import StringIO

# Configuration
firemon_host = 'https://localhost'
username = 'firemon'
password = 'firemon'
device_group_id = 1
control_id = 'd718f39b-2403-4663-8ec7-bb5b02095f95'
cpe_data_path = 'junos_cves.json'
eol_csv_file_path = 'juniper_eol.csv'
ignore_certificate = True  # Ignore certificate validation, useful for self-signed certificates

# Alert options
enable_email_alert = True
output_to_console = True
output_to_csv = True  # Set to False to disable saving CSV locally
output_csv_path = 'juniper_device_findings.csv'

# Logging
enable_logging = True  # Set to False to disable logging
log_file_path = 'firemon_device_check.log'
logging_level = logging.DEBUG  # Set the desired logging level
max_log_size = 10 * 1024 * 1024  # 10 MB
backup_log_count = 5  # Number of backup log files to keep

# Email configuration
include_csv_attachment = True  # True adds CSV attachment, False has results in email body
email_sender = 'JuniperVuls@firemon.com'
email_recipient = 'adam.gunderson@firemon.com'
email_server = 'localhost'
email_port = 25
email_username = ''
email_password = ''
email_subject = 'Vulnerable Juniper Devices Report'
use_smtp_auth = False

# EOL notification configuration
eol_notification_months = 6  # Notify if device will be EOL within this many months
list_all_eol_dates = False  # List all support EOL dates for each device

# Set up logging
if enable_logging:
    handler = RotatingFileHandler(log_file_path, maxBytes=max_log_size, backupCount=backup_log_count)
    logging.basicConfig(level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[handler])

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
        logging.debug(f'API Response for device {device_id}: {data}')
        regex_matches = data.get('regexMatches', [])
        if regex_matches:
            version_line = regex_matches[0].get('line', '')
            version = version_line.strip().split('<version>')[1].split('</version>')[0]
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
        if enable_logging:
            logging.warning(f'CPE JSON file not found: {json_file_path}')
        return cpe_data
    try:
        with open(json_file_path, 'r') as jsonfile:
            cpe_data = json.load(jsonfile)
        if enable_logging:
            logging.info(f'Parsed CPE data: {cpe_data}')
    except Exception as e:
        if enable_logging:
            logging.error(f'Error parsing CPE data: {e}')
        raise
    return cpe_data

# Function to parse EOL data from a CSV file
def parse_eol_data(csv_file_path):
    eol_data = {}
    if not os.path.exists(csv_file_path):
        if enable_logging:
            logging.warning(f'EOL CSV file not found: {csv_file_path}')
        return eol_data
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
        raise

    # Correct specific EOL date
    if '12.1X47' in eol_data:
        eol_data['12.1X47-D18.2'] = datetime.strptime('2017/02/18', '%Y/%m/%d')

    return eol_data

# Function to parse the version parts correctly, including handling non-numeric parts
def parse_version(version):
    try:
        parts = []
        for part in version.replace('X', '.').replace('R', '.').split('.'):
            sub_parts = []
            for sub_part in part.split('-'):
                if sub_part.isdigit():
                    sub_parts.append(int(sub_part))
                else:
                    sub_parts.append(sub_part)
            parts.append(sub_parts)
        return parts
    except Exception as e:
        if enable_logging:
            logging.error(f'Error parsing version: {e}')
        return []

# Function to check if the device version matches the CPE version pattern
def match_versions(device_version, cpe_version):
    device_parts = parse_version(device_version)
    cpe_parts = parse_version(cpe_version)

    for device_part, cpe_part in zip(device_parts, cpe_parts):
        if device_part == cpe_part or cpe_part == "*":
            continue
        if isinstance(device_part, list) and isinstance(cpe_part, list):
            for dp, cp in zip(device_part, cpe_part):
                if dp != cp and cp != "*":
                    return False
        else:
            return False
    return True

# Function to check if a device is vulnerable based on CPE data
def check_vulnerabilities(device_version, cpe_data):
    cves = []
    for entry in cpe_data:
        cpe_version = entry['cpe'].split(':')[5]
        if match_versions(device_version, cpe_version):
            cves.append(entry['cve'])
    return cves

# Function to check EOL status of a device
def check_eol_status(device_version, eol_data):
    eol_date = None
    device_parts = parse_version(device_version)
    most_specific_length = 0
    for eol_version, date in eol_data.items():
        eol_parts = parse_version(eol_version)
        if device_parts[:len(eol_parts)] == eol_parts and len(eol_parts) > most_specific_length:
            eol_date = date
            most_specific_length = len(eol_parts)
    return eol_date

# Function to send an email with the results
def send_email(subject, body, attachment=None):
    try:
        msg = MIMEMultipart()
        msg['From'] = email_sender
        msg['To'] = email_recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        if attachment:
            part = MIMEApplication(attachment.read(), Name=os.path.basename(output_csv_path))
            part['Content-Disposition'] = f'attachment; filename="{os.path.basename(output_csv_path)}"'
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
    try:
        token = authenticate()
        devices = get_devices(token)

        cpe_data = []
        if os.path.exists(cpe_data_path):
            cpe_data = parse_cpe_data(cpe_data_path)

        eol_data = {}
        if os.path.exists(eol_csv_file_path):
            eol_data = parse_eol_data(eol_csv_file_path)

        if not cpe_data and not eol_data:
            if enable_logging:
                logging.info("No CPE or EOL data available. Nothing to do.")
            return

        findings = []
        total_vulnerable_devices = 0
        total_eol_devices = 0

        for device in devices:
            vendor = device.get('devicePack', {}).get('vendor', '')
            artifact_id = device.get('devicePack', {}).get('artifactId', '')
            management_ip = device.get('managementIp', 'N/A')
            if vendor == 'Juniper Networks' and artifact_id in ['juniper_ex', 'juniper_mseries', 'juniper_srx', 'juniper_qfx']:
                device_id = device.get('id', '')
                device_name = device.get('name', '')
                device_version = get_device_version(token, device_id)
                if device_version:
                    result = {
                        'Device ID': device_id,
                        'Device Name': device_name,
                        'Device Version': device_version,
                        'Management IP': management_ip
                    }

                    has_findings = False

                    if cpe_data:
                        cves = check_vulnerabilities(device_version, cpe_data)
                        if cves:
                            result['Vulnerabilities'] = ', '.join(cves)
                            total_vulnerable_devices += 1
                            has_findings = True

                    if eol_data:
                        eol_date = check_eol_status(device_version, eol_data)
                        if eol_date:
                            result['EOL Date'] = eol_date.strftime('%Y-%m-%d')
                            if eol_date <= datetime.now() + timedelta(days=eol_notification_months * 30):
                                total_eol_devices += 1
                            has_findings = True

                    if has_findings or (list_all_eol_dates and 'EOL Date' in result):
                        findings.append(result)

        if findings:
            if output_to_console:
                for finding in findings:
                    print(finding)
            if output_to_csv:
                with open(output_csv_path, 'w', newline='') as csvfile:
                    fieldnames = ['Device ID', 'Device Name', 'Device Version', 'Management IP']
                    if cpe_data:
                        fieldnames.append('Vulnerabilities')
                    if eol_data:
                        fieldnames.append('EOL Date')
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for finding in findings:
                        writer.writerow(finding)

            if enable_email_alert:
                email_body = (
                    f"Total devices checked: {len(devices)}\n"
                )
                if cpe_data:
                    email_body += f"Devices with vulnerabilities: {total_vulnerable_devices}\n"
                if eol_data:
                    email_body += f"Devices that are EOL: {total_eol_devices}\n"

                if include_csv_attachment:
                    email_body += "\nFindings attached."
                    attachment = open(output_csv_path, 'rb')
                else:
                    email_body += "\nFindings:\n"
                    for finding in findings:
                        email_body += "\n".join([f"{key}: {value}" for key, value in finding.items()]) + "\n\n"
                    attachment = None

                send_email(email_subject, email_body, attachment)

    except Exception as e:
        if enable_logging:
            logging.error(f'Unexpected error: {e}')
        raise

if __name__ == '__main__':
    main()
