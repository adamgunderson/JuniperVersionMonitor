# Juniper Version Monitor for FireMon
Checks for devices running JunOS versions with known vulnerabilities and/or EOL.


## JuniperVersionMonitor.py
Script that checks for vulnerabilities or EOL versions. Can be ran directly on FMOS with no additional python packages, ad-hoc or on a cron schedule. 
This script references juniper_eol.csv (generated using scrapeEOL.py) and juniper_vulnerabilities.csv (generated using scrapeMitre.py).


## scrapeEOL.py
This script is used to scrape EOL versions and dates from juniper.net and saves them in juniper_eol.csv.

Additional Python Libraries are required:
- pip install selenium
- pip install webdriver_manager
- pip install beautifulsoup4


## scrapeMitre.py
This script is used to scrape CVE's and vulnerable JunOS versions from mitre.org and saves them in juniper_vulnerabilities.csv.

Additional Python Libraries are required:
- pip install beautifulsoup4
