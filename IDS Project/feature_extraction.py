
from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import WHOIS as ch
import Onmouse as om
import PhishTank as pt
import websitetraffic as wbt
import checkhttp as http 

def redirect_check(url):
    if url.startswith("https://"):
        ex_pos = 7
    else:
        ex_pos = 6
    return -1 if url.find('//', ex_pos) > ex_pos else 1

#Checks for shortening service urls 
def is_shortened_url(url):
    shortening_services = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "ow.ly", "adf.ly", "shorte.st", "buff.ly"
]
    for service in shortening_services:
        if service in url:
            return -1 
    return 1 



def check_subdomains(url):
    # Parse the URL to extract the domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Remove 'www.' if present
    if domain.startswith("www."):
        domain = domain[4:]

    # Split the domain into parts (e.g., 'example.co.za' -> ['example', 'co', 'za'])
    domain_parts = domain.split('.')

    # Count the number of domain components (including the ccTLD)
    if len(domain_parts) > 3:
        return -1
    else:
        return 1

def submit_to_email(url):
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form', action=re.compile(r'^mailto:', re.IGNORECASE))
        return -1 if forms else 1
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return 0
    
    
def url_leng(url):
    if len(url) < 54:
        return 1
    elif 54 <= len(url) <= 75:
        return 0
    else:
        return -1
def clean_url(url):
    # Remove the protocol
    if url.startswith('http://'):
        url = url[7:]
    elif url.startswith('https://'):
        url = url[8:]
    # Remove 'www.' if present
    if url.startswith('www.'):
        url = url[4:]
    # Split by '/' and take the first part (domain)
    domain = url.split('/')[0]
    return domain 
    
    
def dotcount(url): 
    cleaned_url = clean_url(url)
    # Count the dots in the domain part
    dot_count = cleaned_url.count('.')
    # Classification based on dot count
    if dot_count <= 2:
        return 1
    elif dot_count == 3:
        return 0
    else:
        return -1
    
def ipUsage(url): 
    cleaned_url = clean_url(url)
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',cleaned_url):
        return -1
    else: return  1 
    # Function that extracts features from URL(A combination of other methods into one)
def extract_features(url):
    StatsReport = pt.database_check(url)  # -1 if phishing, 1 if legitimate
    WebsiteTraffic = wbt.lookup_sites(url)
    UsingIP = ipUsage(url)
    LongURL = url_leng(url)
    SymbolAt = -1 if "@" in url else 1
    Redirecting = redirect_check(url)
    domain = urlparse(url).netloc
    PrefixSuffix = -1 if '-' in domain else 1
    Subdomains = check_subdomains(url)
    HTTPS = http.check_https_details(url)
    DomainRegLen = ch.check_expiry_date(url)
    InfoEmail = submit_to_email(url)
    AgeofDomain = ch.check_creation_date(url)
    ShortURL = is_shortened_url(url)
    return [StatsReport, WebsiteTraffic, UsingIP, LongURL, SymbolAt, Redirecting, PrefixSuffix, Subdomains, HTTPS, DomainRegLen, InfoEmail, AgeofDomain, ShortURL]
