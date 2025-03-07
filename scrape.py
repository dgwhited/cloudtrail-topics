import requests
from bs4 import BeautifulSoup
import re
import json
import os

BASE_CLOUDTRAIL_URL = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html"


def get_cloudtrail_html(link):
    """
    Scrapes a webpage and returns it parsed by BeautifulSoup
    """
    try:
        # Allow redirects with a timeout
        response = requests.get(link, allow_redirects=True, timeout=30)
        response.raise_for_status()  # Raise exception for 4XX/5XX responses
        soup = BeautifulSoup(response.content, "html.parser")
        return soup
    except requests.exceptions.RequestException as e:
        print(f"Error fetching main page: {e}")
        raise


def parse_cloudtrail_html(soup):
    h2 = soup.find('h2', id='cloudtrail-aws-service-specific-topics-organizations')
    data = {}
    if h2:
        table = h2.find_next('table')
        if table:
            headers = [th.text.strip() for th in table.select('thead th')]
            for row in table.find_all('tr', recursive=False):
                cells = row.find_all(['th', 'td'])
                if cells:
                    values = []
                    links = []
                    for cell in cells:
                        link = cell.find('a')
                        if link:
                            text = link.text.strip()
                            url = link['href']
                            values.append(text)
                            links.append(url)
                        else:
                            values.append(cell.text.strip())
                            links.append('')
                    if len(values) == len(headers):
                        row_data = dict(zip(headers, values))
                        row_data['Link'] = links[1] if len(links) > 1 else ''
                        data[values[0]] = row_data
    return data


def clean_dict_data(data):
    cleaned_data = {}
    
    for key, value in data.items():
        cleaned_key = re.sub(r'\s+', ' ', key.strip())
        cleaned_value = {}
        
        for sub_key, sub_value in value.items():
            cleaned_sub_key = re.sub(r'\s+', ' ', sub_key.strip())
            
            if '<a href' in sub_value:
                # If the sub-value contains a link, extract the URL and text
                soup = BeautifulSoup(sub_value, 'html.parser')
                link = soup.find('a')
                if link:
                    url = link['href']
                    text = link.text.strip()
                    cleaned_sub_value = re.sub(r'\s+', ' ', text)
                    cleaned_sub_value = f'{cleaned_sub_value} ({url})'
                else:
                    cleaned_sub_value = re.sub(r'\s+', ' ', sub_value.strip())
            else:
                cleaned_sub_value = re.sub(r'\s+', ' ', sub_value.strip())
            
            cleaned_value[cleaned_sub_key] = cleaned_sub_value
        
        cleaned_data[cleaned_key] = cleaned_value
    
    return cleaned_data


def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def scrape_and_save(url, directory, filename):
    try:
        # Allow redirects but with a higher limit, and add a timeout
        response = requests.get(url, allow_redirects=True, timeout=30)
        soup = BeautifulSoup(response.text, 'html.parser')
        content = soup.prettify()
        
        filepath = os.path.join(directory, filename)
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"Successfully saved {filename}")
    except requests.exceptions.TooManyRedirects:
        print(f"Error: Too many redirects for {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")


def process_dictionary(data, directory):
    create_directory(directory)
    
    for item in data.values():
        url = item['Link']
        if url:
            # Handle relative URLs by prepending the base domain if needed
            if url.startswith('/'):
                url = f"https://docs.aws.amazon.com{url}"
            
            service_name = item['AWS Service']
            # Clean filename to avoid invalid characters
            filename = f"{service_name.replace('/', '-').replace(':', '-')}.html"
            
            scrape_and_save(url, directory, filename)
        else:
            continue


def main():
    docs = get_cloudtrail_html(BASE_CLOUDTRAIL_URL)
    table = parse_cloudtrail_html(docs)
    cleaned_data = clean_dict_data(table)
    with open("./cloudtrail-topics.json", 'w', encoding='utf-8') as file:
        file.write(json.dumps(cleaned_data, indent=2))
    process_dictionary(cleaned_data, "./cloudtrail-html-topics")


if __name__ == '__main__':
    main()
