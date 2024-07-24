# Juniper Version Monitor for FireMon
Checks for devices running JunOS versions with known vulnerabilities and/or EOL.


## JuniperVersionMonitor.py
Script that checks for vulnerabilities or EOL versions. Can be ran directly on FMOS with no additional python packages, ad-hoc or on a cron schedule. 
This script references juniper_eol.csv (generated using scrapeEOL.py) and junos_cves.json (generated using fetchJunosCVE.py).

## fetchJunosCVE.py
This script downloaded CPE and CVE data from nvd.nist.gov and stored as junos_cves.json. API key is optional. Rate limit to 5 requests per 30 seconds if no API key, and 50 requests per 30 seconds with API key.
Standard FMOS Python libraries are used, so this can be ran directly in FMOS.

## scrapeEOL.py
This script is used to scrape EOL versions and dates from juniper.net and saves them in juniper_eol.csv.

Additional Python Libraries are required:
```console
pip install selenium
```
```console
pip install webdriver_manager
```
```console
pip install beautifulsoup4
```

### Running scrapeEOL.py in FMOS ###
Installing these additional libraries on FMOS requires the use of a python virtual environment (venv). Follow the instructions below to create a a python virtual environment and set the script to run on the cron schedule.

Create the venv
```console
/usr/lib/firemon/devpackfw/bin/python -m venv eol-scrape
```
Activate venv.
```console
source eol-scrape/bin/activate
```
Install pip.
```console
python3 eol-scrape/bin/pip install -U pip
```
Now we can install the required libraries.
```console
python3 eol-scrape/bin/pip install requests
```
```console
python3 eol-scrape/bin/pip install BeautifulSoup4
```
```console
python3 eol-scrape/bin/pip install webdriver_manager
```
```console
python3 eol-scrape/bin/pip install chardet 
```
Test that the script now runs successfully.
```console
python3 scrapeEOL.py 
```
Create the cronjob for the script to run. The EOL pages likely don't update very often so it would be reasonable for the cron run infrequently. The following cron example will run the script once per month. 
Check your home directory path.
```console
pwd
```
> /home/firemon/ 
 
Set the cron expression
```console
crontab -e
```
> 0 0 1 * * cd /home/firemon $$ /home/firemon/eol-scrape/bin/python /home/firemon/scrapeEOL.py > /dev/null 2>&1

To exit the python virtual environemnt type:
```console
deactivate
```

