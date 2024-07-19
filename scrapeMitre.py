import requests
from bs4 import BeautifulSoup
import pandas as pd
import re

# URL to scrape
url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Junos"

# Send a request to the URL
response = requests.get(url)
response.raise_for_status()  # Check if the request was successful

# Parse the HTML content
soup = BeautifulSoup(response.content, 'html.parser')

# Find all rows in the table
rows = soup.find_all('tr')

# Function to clean and split version strings
def extract_versions(description):
    # Use regular expressions to find valid version strings preceded by 'before'
    version_patterns = re.findall(r'\b(?:before\s+([\d\.\-\w]+))', description, re.IGNORECASE)
    return version_patterns

# Function to check if a string is a valid Junos version format
def is_valid_version(version):
    return re.match(r'^\d{1,2}\.\d{1,2}[R\.\-\w]*$', version) is not None

# Extract CVE ID and description
data = []
for row in rows:
    columns = row.find_all('td')
    if len(columns) == 2:
        cve_id = columns[0].find('a').text
        description = columns[1].text
        # Extract version information from the description
        versions = extract_versions(description)
        if versions:
            for version in versions:
                version = version.strip().rstrip('.')
                # Ensure that the version string is valid
                if is_valid_version(version):
                    data.append({"Version": version, "CVE ID": cve_id})

# Convert to DataFrame
df_extracted = pd.DataFrame(data)

# Remove any duplicates
df_extracted = df_extracted.drop_duplicates()

# Save to CSV
csv_file_path_extracted = "juniper_vulnerabilities.csv"
df_extracted.to_csv(csv_file_path_extracted, index=False)

print(f"CSV file saved to {csv_file_path_extracted}")
