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
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
import time
from threading import Lock

#########################
## Begin Configuration ##
#########################

# Configuration
firemon_host = 'https://localhost'  # Script can be ran directly on FMOS app server
username = 'firemon'  # FireMon GUI username
password = 'firemon'  # FireMon GUI password
device_group_id = 1
control_id = 'd718f39b-2403-4663-8ec7-bb5b02095f95'  # Update this to match the uploaded control UUID
eol_csv_file_path = 'juniper_eol.csv'  # Input file of Junos Version and EOL dates
ignore_certificate = True  # Ignore certificate validation, useful for self-signed certificates
cvss_threshold = 4.0  # Ignore CVEs with a CVSS score below this value

# EOL checking configuration
eol_notification_months = 6  # List if device will be EOL within this many months

# Alert options
enable_email_alert = True
output_to_console = True
output_to_csv = True  # Set to False to disable saving CSV locally
output_csv_path = 'juniper_version_report.csv'
cve_csv_path = 'juniper_cve_report.csv'  # New CSV file path for CVE details

# Logging
enable_logging = True  # Set to False to disable logging
log_file_path = 'juniper_version_report.log'
logging_level = logging.INFO  # Set the desired logging level
max_log_size = 5 * 1024 * 1024  # 5 MB (reduced from 10 MB)
backup_log_count = 10  # Reduced from 50 to keep fewer backup files

# Email configuration
include_csv_attachment = True  # True adds CSV attachment, False has results in email body
email_sender = 'JuniperVersionReport@firemon.com'
email_recipient = 'adam.gunderson@firemon.com'  # Use your own email address unless you want me to get your report
email_server = 'localhost'
email_port = 25
email_username = ''
email_password = ''
email_subject = 'Juniper Version Report'
use_smtp_auth = False

# New configuration variables
NVD_API_KEY = ''  # Replace with your actual NVD API key
CVE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FIREMON_MAX_WORKERS = 10  # Maximum number of worker threads for FireMon API calls
NVD_MAX_WORKERS = 1  # Maximum number of worker threads for NVD API calls

#######################
## End Configuration ##
#######################

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

# Rate limiter class
class RateLimiter:
    def __init__(self, max_calls, period):
        self.max_calls = max_calls
        self.period = period
        self.calls = deque()
        self.lock = Lock()

    def wait(self):
        with self.lock:
            if len(self.calls) >= self.max_calls:
                elapsed = time.time() - self.calls[0]
                if elapsed < self.period:
                    time.sleep(self.period - elapsed)
            self.calls.append(time.time())
            if len(self.calls) > self.max_calls:
                self.calls.popleft()

# Create rate limiter for NVD API
nvd_rate_limiter = RateLimiter(50 if NVD_API_KEY else 5, 30)

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

# Function to parse EOL data from a CSV file
def parse_eol_data(csv_file_path):
    eol_data = {}
    if not os.path.exists(csv_file_path):
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

# Add the parse_version function here
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

# Update the check_eol_status function to use the new parse_version function
def check_eol_status(device_version, eol_data):
    eol_date = None
    most_specific_length = 0
    device_parts = parse_version(device_version)
    for version, date in eol_data.items():
        eol_parts = parse_version(version)
        if len(eol_parts) <= len(device_parts) and all(dp == ep for dp, ep in zip(device_parts, eol_parts)):
            if len(eol_parts) > most_specific_length:
                eol_date = date
                most_specific_length = len(eol_parts)
    return eol_date

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

# Updated function to check vulnerabilities for a specific Junos version
def check_vulnerabilities(junos_version):
    cpe = f"cpe:2.3:o:juniper:junos:{junos_version}:*:*:*:*:*:*:*"
    params = {
        "cpeName": cpe,
        "resultsPerPage": 2000
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    vulnerabilities = []
    try:
        nvd_rate_limiter.wait()  # Wait for rate limit
        response = requests.get(CVE_BASE_URL, params=params, headers=headers, verify=not ignore_certificate)
        response.raise_for_status()
        cve_data = response.json()
        
        if cve_data and 'vulnerabilities' in cve_data:
            for vuln in cve_data['vulnerabilities']:
                cve = vuln['cve']
                cvss_v31 = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
                cvss_v2 = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {})
                
                severity = cvss_v31.get('baseSeverity') or cvss_v2.get('baseSeverity') or "N/A"
                cvss_score = cvss_v31.get('baseScore') or cvss_v2.get('baseScore') or "N/A"
                
                if cvss_score != "N/A" and float(cvss_score) < cvss_threshold:
                    continue

                vendor_advisory = "N/A"
                for ref in cve.get('references', []):
                    if "Vendor Advisory" in ref.get('tags', []):
                        vendor_advisory = ref.get('url', "N/A")
                        break

                vulnerabilities.append({
                    "cve_id": cve['id'],
                    "description": cve['descriptions'][0]['value'] if cve['descriptions'] else "N/A",
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "vendor_advisory": vendor_advisory
                })

    except requests.exceptions.RequestException as e:
        if enable_logging:
            logging.error(f'Error checking vulnerabilities for version {junos_version}: {e}')

    return vulnerabilities

# Updated function to process each device
def process_device(token, device, eol_data, eol_data_exists):
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

            if eol_data_exists and eol_data:
                eol_date = check_eol_status(device_version, eol_data)
                if eol_date and eol_date <= datetime.now() + timedelta(days=eol_notification_months * 30):
                    result['EOL Date'] = eol_date.strftime('%Y-%m-%d')
                    has_findings = True

            if has_findings or True:  # Always return the result for Juniper devices
                result['Junos OS Type'] = 'Junos OS Evolved' if '-EVO' in device_version else 'Junos'
                return result, is_juniper, device_version
        else:
            logging.warning(f"Could not retrieve version for Juniper device: {device.get('name', 'Unknown')}")
            return None, is_juniper, None
    return None, is_juniper, None

# New function to check vulnerabilities for a batch of devices
def check_vulnerabilities_batch(devices_versions):
    cve_details = defaultdict(set)
    for device_name, management_ip, device_version in devices_versions:
        cves = check_vulnerabilities(device_version.replace("-EVO", ""))
        for cve in cves:
            cve_key = (cve['cve_id'], cve['description'], cve['severity'], cve['cvss_score'], cve['vendor_advisory'])
            device_info = f"{device_name} ({management_ip})"
            cve_details[cve_key].add(device_info)
    return cve_details

# Updated main function
def main():
    start_time = datetime.now()
    try:
        token = authenticate()
        devices = get_devices(token)

        eol_data = {}
        eol_data_exists = os.path.exists(eol_csv_file_path)
        if eol_data_exists:
            eol_data = parse_eol_data(eol_csv_file_path)

        findings = []
        juniper_devices = []
        total_juniper_devices = 0
        total_devices = len(devices)
        total_eol_devices = 0  # Initialize EOL counter

        # Process devices using FireMon API
        with ThreadPoolExecutor(max_workers=FIREMON_MAX_WORKERS) as executor:
            futures = [executor.submit(process_device, token, device, eol_data, eol_data_exists) for device in devices]
            for future in as_completed(futures):
                result, is_juniper, device_version = future.result()
                if is_juniper:
                    total_juniper_devices += 1
                    if result:
                        findings.append(result)
                        if device_version:
                            juniper_devices.append((result['Device Name'], result['Management IP'], device_version))
                        if eol_data_exists and 'EOL Date' in result:
                            total_eol_devices += 1  # Count EOL devices
                    else:
                        logging.warning(f"No result for Juniper device with version: {device_version}")

        # Check vulnerabilities using NVD API
        cve_details = defaultdict(set)
        with ThreadPoolExecutor(max_workers=NVD_MAX_WORKERS) as executor:
            chunk_size = 10  # Adjust this value based on your needs
            futures = []
            for i in range(0, len(juniper_devices), chunk_size):
                chunk = juniper_devices[i:i+chunk_size]
                futures.append(executor.submit(check_vulnerabilities_batch, chunk))
            for future in as_completed(futures):
                chunk_cve_details = future.result()
                for cve_key, devices in chunk_cve_details.items():
                    cve_details[cve_key].update(devices)

        # Update findings with vulnerability information
        total_vulnerable_devices = 0
        for finding in findings:
            device_info = f"{finding['Device Name']} ({finding['Management IP']})"
            finding_cves = [cve_key[0] for cve_key, devices in cve_details.items() if device_info in devices]
            if finding_cves:
                finding['Vulnerabilities'] = ', '.join(finding_cves)
                total_vulnerable_devices += 1

        end_time = datetime.now()
        run_duration = (end_time - start_time).total_seconds()

        # Construct email body
        email_body = (
            f"Total devices in device group: {total_devices}\n"
            f"Total Juniper devices checked: {total_juniper_devices}\n"
            f"Total devices with vulnerabilities: {total_vulnerable_devices}\n"
        )
        
        # Only include EOL information if the EOL data file was provided
        if eol_data_exists:
            email_body += f"Total devices with EOL versions: {total_eol_devices}\n"

        email_body += (
            f"Script start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Script end time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Script run duration: {round(run_duration)} seconds\n"
        )

        if output_to_console:
            for finding in findings:
                print(finding)
            print(email_body)

        if output_to_csv:
            fieldnames = ['Device ID', 'Device Name', 'Device Version', 'Management IP', 'Vulnerabilities', 'Junos OS Type']
            if eol_data_exists:
                fieldnames.insert(-1, 'EOL Date')

            with open(output_csv_path, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for finding in findings:
                    writer.writerow(finding)

            # Write the CVE details to the second CSV
            cve_fieldnames = ['cve_id', 'description', 'severity', 'cvss_score', 'vendor_advisory', 'Device Count']
            with open(cve_csv_path, 'w', newline='') as cvefile:
                writer = csv.DictWriter(cvefile, fieldnames=cve_fieldnames)
                writer.writeheader()
                for cve_key, devices in cve_details.items():
                    cve_data = {
                        'cve_id': cve_key[0],
                        'description': cve_key[1],
                        'severity': cve_key[2],
                        'cvss_score': cve_key[3],
                        'vendor_advisory': cve_key[4],
                        'Device Count': len(devices)
                    }
                    writer.writerow(cve_data)

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
