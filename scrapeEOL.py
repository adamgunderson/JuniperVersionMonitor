import csv
import re
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup

def get_html_content(url):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920x1080")

    driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
    
    driver.get(url)
    page_source = driver.page_source
    driver.quit()
    
    soup = BeautifulSoup(page_source, 'html.parser')
    table = soup.find('table')
    if table:
        return table
    else:
        print("Error: Could not find the table in the HTML content.")
        return None

def clean_product_name(product_name):
    soup = BeautifulSoup(product_name, 'html.parser')
    # Remove all <sup> tags and their contents
    for sup in soup.find_all('sup'):
        sup.decompose()
    # Get text and strip any surrounding whitespace
    cleaned_name = soup.get_text().strip()
    # Further clean up by removing any remaining unwanted characters and extra spaces
    cleaned_name = re.sub(r'[^a-zA-Z0-9\s\.\-X]', '', cleaned_name).strip()
    return cleaned_name

def parse_table(table):
    rows = table.find_all('tr')
    header = [th.text.strip() for th in rows[0].find_all('th')]
    data = []
    
    for row in rows[1:]:
        columns = row.find_all('td')
        if len(columns) > 0:
            product_name = str(columns[0])
            cleaned_product_name = clean_product_name(product_name)
            cleaned_row = [cleaned_product_name] + [col.text.strip() for col in columns[1:]]
            data.append(cleaned_row)
    
    return header, data

def save_to_csv(header, data, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(data)

def main():
    url = 'https://support.juniper.net/support/eol/software/junos'
    table = get_html_content(url)
    if table:
        header, data = parse_table(table)
        save_to_csv(header, data, 'juniper_eol.csv')
        print(f"Data saved to 'juniper_eol.csv'.")
    else:
        print("No HTML content extracted.")

if __name__ == '__main__':
    main()
