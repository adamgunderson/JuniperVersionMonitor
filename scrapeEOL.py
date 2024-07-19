import csv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup

def get_html_content(url):
    # Set up Selenium with Chrome
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems
    chrome_options.add_argument("--no-sandbox")  # Bypass OS security model
    chrome_options.add_argument("--disable-gpu")  # Applicable to windows os only
    chrome_options.add_argument("--window-size=1920x1080")  # Set window size

    driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
    
    # Load the page
    driver.get(url)
    
    # Get the page source
    page_source = driver.page_source
    
    # Close the browser
    driver.quit()
    
    # Parse the HTML with BeautifulSoup
    soup = BeautifulSoup(page_source, 'html.parser')
    
    # Find the table with EOL information
    table = soup.find('table')
    if table:
        return table
    else:
        print("Error: Could not find the table in the HTML content.")
        return None

def parse_table(table):
    rows = table.find_all('tr')
    header = [th.text.strip() for th in rows[0].find_all('th')]
    data = []
    
    for row in rows[1:]:
        columns = row.find_all('td')
        if len(columns) > 0:
            data.append([col.text.strip() for col in columns])
    
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
