import sys
import smtplib
import requests
import json
import time
import logging
from logging.handlers import RotatingFileHandler
from collections import deque
from threading import Lock

API_KEY = 'ec1ff6ac-cbbb-411c-bedf-30834fda6844'
CPE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_MATCH_STRINGS = [
    "cpe:2.3:o:juniper:junos",
    "cpe:2.3:o:juniper:junos_os_evolved",
    "cpe:2.3:h:juniper"
]
MAX_CPE_LIMIT = None  # Set the limit for the number of CPEs to fetch CVEs for, or None for no limit

# Set up logging
log_file = "fetchJunosCVE.log"
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(log_file, maxBytes=5000000, backupCount=5)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.DEBUG)

logger = logging.getLogger('fetchJunosCVE')
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

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

rate_limiter = RateLimiter(50 if API_KEY else 5, 30)

def api_request(url, params, headers):
    rate_limiter.wait()
    response = requests.get(url, params=params, headers=headers)
    logger.debug(f"Requesting with URL: {response.url}")  # Debug logging
    if response.status_code == 200:
        return response
    else:
        logger.error(f"Failed to fetch data: {response.status_code}")
        logger.error(response.text)
        return None

def get_cpes():
    cpes = []
    for cpe_match_string in CPE_MATCH_STRINGS:
        params = {
            "cpeMatchString": cpe_match_string,
            "resultsPerPage": 10000,
            "startIndex": 0
        }
        headers = {}
        if API_KEY:
            headers["apiKey"] = API_KEY

        while True:
            response = api_request(CPE_BASE_URL, params, headers)
            if response:
                try:
                    cpe_data = response.json()
                    if 'products' in cpe_data and len(cpe_data['products']) > 0:
                        logger.debug(json.dumps(cpe_data['products'][0], indent=4))

                    for product in cpe_data['products']:
                        cpe_entry = product['cpe']
                        cpe_name = cpe_entry['cpeName']

                        if "-:*:*:*:*:*:*:*" not in cpe_name:
                            cpes.append(cpe_name)

                    if params['startIndex'] + params['resultsPerPage'] >= cpe_data['totalResults'] or (MAX_CPE_LIMIT and len(cpes) >= MAX_CPE_LIMIT):
                        break
                    params['startIndex'] += params['resultsPerPage']
                except json.JSONDecodeError:
                    logger.error("Error decoding JSON response for CPEs")
                    logger.error(response.text)
                    break
            else:
                break

    return cpes[:MAX_CPE_LIMIT] if MAX_CPE_LIMIT else cpes

def parse_cve(cve, cpe):
    description = cve['cve']['descriptions'][0]['value'] if 'descriptions' in cve['cve'] and cve['cve']['descriptions'] else "N/A"
    
    # Extract CVSS v3.1 metrics
    cvss_v31 = cve['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
    
    severity = cvss_v31.get('baseSeverity', "N/A")
    cvss_score = cvss_v31.get('baseScore', "N/A")
    attack_vector = cvss_v31.get('attackVector', "N/A")
    attack_complexity = cvss_v31.get('attackComplexity', "N/A")
    availability_impact = cvss_v31.get('availabilityImpact', "N/A")
    
    # Extract exploitability and impact scores
    exploitability_score = cve['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('exploitabilityScore', "N/A")
    impact_score = cve['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('impactScore', "N/A")

    return {
        "cpe": cpe,
        "cve": cve['cve']['id'],
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "attackVector": attack_vector,
        "attackComplexity": attack_complexity,
        "availabilityImpact": availability_impact,
        "exploitabilityScore": exploitability_score,
        "impactScore": impact_score
    }

def get_cves(cpe):
    params = {
        "cpeName": cpe,
        "startIndex": 0,
        "resultsPerPage": 2000
    }
    headers = {}
    if API_KEY:
        headers["apiKey"] = API_KEY

    cves = []
    while True:
        response = api_request(CVE_BASE_URL, params, headers)
        if response:
            try:
                cve_data = response.json()
                cves.extend(cve_data['vulnerabilities'])
                if params['startIndex'] + params['resultsPerPage'] >= cve_data['totalResults']:
                    break
                params['startIndex'] += params['resultsPerPage']
            except json.JSONDecodeError:
                logger.error(f"Error decoding JSON response for CVEs for CPE {cpe}")
                logger.error(response.text)
                break
        else:
            break

    return cves

def main():
    cpes = get_cpes()
    result = []

    for cpe in cpes:
        logger.debug(f"Fetching CVEs for CPE: {cpe}")
        cves = get_cves(cpe)
        for cve in cves:
            logger.debug(f"CVE API response: {json.dumps(cve, indent=4)}")
            cve_info = parse_cve(cve, cpe)
            result.append(cve_info)

    with open('junos_cves.json', 'w') as f:
        json.dump(result, f, indent=4)
    
    logger.info("Data saved to junos_cves.json")

if __name__ == "__main__":
    main()
