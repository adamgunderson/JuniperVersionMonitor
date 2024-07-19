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
from datetime import datetime, timedelta
from io import StringIO

# Configuration
firemon_host = 'https://localhost'
username = 'firemon'
password = 'firemon'
device_group_id = 1
control_id = 'eca59354-4bdb-4754-acb2-eeffb756860d'
vulnerabilities_csv_path = 'juniper_vulnerabilities.csv'  # Input file of vulnerabilities, gernerated with scrapeMitre.py
eol_csv_file_path = 'juniper_eol.csv'  # Input file of EOL versions and dates, generated with scrapeMitre.py
ignore_certificate = True  # Ignore SSL certificate, useful for self-signed certs.

# EOL notification configuration
eol_notification_months = 6  # Notify if device will be EOL within this many months
list_all_eol_dates = True  # List all support EOL dates for each device

# Alert options
output_to_console = True
output_to_csv = True  # Set to False to disable saving CSV locally
output_csv_path = 'vulnerable_devices_report.csv'
enable_email_alert = True

# Email configuration
include_csv_attachment = True
email_sender = 'JuniperVuls@firemon.com'
email_recipient = 'adam.gunderson@firemon.com'
email_server = 'localhost'
email_port = 25
email_username = ''
email_password = ''
email_subject = 'Vulnerable Juniper Devices Report'
use_smtp_auth = False

# Logging
enable_logging = True  # Set to False to disable logging
log_file_path = 'firemon_device_check.log'
logging_level = logging.DEBUG  # Set the desired logging level
max_log_size = 10 * 1024 * 1024  # 10 MB
backup_log_count = 5  # Number of backup log files to keep

#################################################
##        NO CONFIGURATION NEEDED BELOW        ##
#################################################

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

# Function to parse vulnerabilities from a CSV file
def parse_vulnerabilities(csv_file_path):
    vulnerabilities = {}
    if not os.path.exists(csv_file_path):
        if enable_logging:
            logging.warning(f'Vulnerability CSV file not found: {csv_file_path}')
        return vulnerabilities
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
    return eol_data

# Function to parse the version parts correctly, including handling non-numeric parts
def parse_version(version):
    try:
        parts = version.replace('X', '.').replace('R', '.').split('.')
        return [int(part) if part.isdigit() else part for part in parts]
    except Exception as e:
        if enable_logging:
            logging.error(f'Error parsing version: {e}')
        return []

# Function to compare versions considering sub-versions
def is_version_affected(device_version, vuln_version):
    device_parts = parse_version(device_version)
    vuln_parts = parse_version(vuln_version)
    return device_parts[:len(vuln_parts)] == vuln_parts

# Function to check if a device is vulnerable
def check_vulnerabilities(device_version, vulnerabilities):
    cves = []
    for vuln_version, vuln_cves in vulnerabilities.items():
        if is_version_affected(device_version, vuln_version):
            cves.extend(vuln_cves)
    return list(set(cves))

# Function to check EOL status
def check_eol_status(device_version, eol_data):
    eol_date = None
    for eol_version, date in eol_data.items():
        if is_version_affected(device_version, eol_version):
            eol_date = date
            break
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
        vulnerabilities = parse_vulnerabilities(vulnerabilities_csv_path)
        eol_data = parse_eol_data(eol_csv_file_path)

        findings = []

        for device in devices:
            vendor = device.get('devicePack', {}).get('vendor', '')
            artifact_id = device.get('devicePack', {}).get('artifactId', '')
            if vendor == 'Juniper Networks' and artifact_id in ['juniper_ex', 'juniper_mseries', 'juniper_srx', 'juniper_qfx']:
                device_id = device.get('id', '')
                device_name = device.get('name', '')
                device_version = get_device_version(token, device_id)
                if device_version:
                    cves = check_vulnerabilities(device_version, vulnerabilities)
                    eol_date = check_eol_status(device_version, eol_data)
                    if cves or (eol_date and eol_date <= datetime.now() + timedelta(days=eol_notification_months*30)) or list_all_eol_dates:
                        findings.append({
                            'Device Name': device_name,
                            'Device Version': device_version,
                            'Vulnerabilities': ', '.join(cves) if cves else 'None',
                            'EOL Date': eol_date.strftime('%Y-%m-%d') if eol_date else 'None'
                        })

        if findings:
            if output_to_console:
                for finding in findings:
                    print(finding)
            if output_to_csv:
                with open(output_csv_path, 'w', newline='') as csvfile:
                    fieldnames = ['Device Name', 'Device Version', 'Vulnerabilities', 'EOL Date']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for finding in findings:
                        writer.writerow(finding)

            if enable_email_alert:
                email_body = 'Findings attached.' if include_csv_attachment else '\n'.join([str(f) for f in findings])
                attachment = open(output_csv_path, 'rb') if include_csv_attachment else None
                send_email(email_subject, email_body, attachment)

    except Exception as e:
        if enable_logging:
            logging.error(f'Unexpected error: {e}')
        raise

if __name__ == '__main__':
    main()
