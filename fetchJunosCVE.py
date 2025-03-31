#!/usr/bin/python
import sys
import os
import json
import time

def ensure_module(module_name):
    """Dynamically import a module by searching for it in potential site-packages locations"""
    # First try the normal import in case it's already in the path
    try:
        return __import__(module_name)
    except ImportError:
        pass
    
    # Get the current Python version
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    
    # Create a list of potential paths to check
    base_path = '/usr/lib/firemon/devpackfw/lib'
    potential_paths = [
        # Current Python version
        f"{base_path}/python{py_version}/site-packages",
        # Exact Python version with patch
        f"{base_path}/python{sys.version.split()[0]}/site-packages",
        # Try a range of nearby versions (for future-proofing)
        *[f"{base_path}/python3.{i}/site-packages" for i in range(8, 20)]
    ]
    
    # Try each path
    for path in potential_paths:
        if os.path.exists(path):
            if path not in sys.path:
                sys.path.append(path)
            try:
                return __import__(module_name)
            except ImportError:
                continue
    
    # If we get here, we couldn't find the module
    raise ImportError(f"Could not find module {module_name} in any potential site-packages location")

# Import required modules
requests = ensure_module("requests")
smtplib = ensure_module("smtplib")

API_KEY = ""  # Set this to None or "" if no API key is used
CPE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Function to get CPEs for Juniper Junos
def get_cpes():
    cpe_match_string = "cpe:2.3:o:juniper:junos"
    params = {
        "cpeMatchString": cpe_match_string,
        "resultsPerPage": 10000,
        "startIndex": 0
    }
    headers = {}
    if API_KEY:
        headers["apiKey"] = API_KEY
    
    cpes = []
    while True:
        response = requests.get(CPE_BASE_URL, params=params, headers=headers)
        print(f"Requesting CPEs with URL: {response.url}")  # Debug logging
        if response.status_code == 200:
            try:
                cpe_data = response.json()
                # Debug: Print the structure of the first item in 'products'
                if 'products' in cpe_data and len(cpe_data['products']) > 0:
                    print(json.dumps(cpe_data['products'][0], indent=4))
                
                for product in cpe_data['products']:
                    cpe_entry = product['cpe']
                    cpe_name = cpe_entry['cpeName']
                    
                    # Exclude wide open CPEs
                    if "-:*:*:*:*:*:*:*" not in cpe_name:
                        cpes.append(cpe_name)

                if params['startIndex'] + params['resultsPerPage'] >= cpe_data['totalResults']:
                    break
                params['startIndex'] += params['resultsPerPage']
                if not API_KEY:
                    time.sleep(6)  # Rate limit to 5 requests per 30 seconds if no API key
                else:
                    time.sleep(0.6)  # To avoid hitting rate limits (50 requests per 30 seconds with API key)
            except json.JSONDecodeError:
                print("Error decoding JSON response for CPEs")
                print(response.text)
                break
        else:
            print(f"Failed to fetch CPEs: {response.status_code}")
            print(response.text)
            break

    return cpes

# Function to get CVEs for a given CPE
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
        response = requests.get(CVE_BASE_URL, params=params, headers=headers)
        print(f"Requesting CVEs with URL: {response.url}")  # Debug logging
        if response.status_code == 200:
            try:
                cve_data = response.json()
                cves.extend(cve_data['vulnerabilities'])
                if params['startIndex'] + params['resultsPerPage'] >= cve_data['totalResults']:
                    break
                params['startIndex'] += params['resultsPerPage']
                if not API_KEY:
                    time.sleep(6)  # Rate limit to 5 requests per 30 seconds if no API key
                else:
                    time.sleep(0.6)  # To avoid hitting rate limits (50 requests per 30 seconds with API key)
            except json.JSONDecodeError:
                print(f"Error decoding JSON response for CVEs for CPE {cpe}")
                print(response.text)
                break
        else:
            print(f"Failed to fetch CVEs for CPE {cpe}: {response.status_code}")
            print(response.text)
            break

    return cves

# Main function to get CPEs, then fetch CVEs for each CPE, and store results in JSON
def main():
    cpes = get_cpes()
    result = []

    for cpe in cpes:
        print(f"Fetching CVEs for CPE: {cpe}")
        cves = get_cves(cpe)
        for cve in cves:
            cve_info = {
                "cpe": cpe,
                "cve": cve['cve']['id']
            }
            result.append(cve_info)

    with open('junos_cves.json', 'w') as f:
        json.dump(result, f, indent=4)
    
    print("Data saved to junos_cves.json")

if __name__ == "__main__":
    main()
