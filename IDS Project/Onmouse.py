import requests as res
from bs4 import BeautifulSoup
import re


def on_mouse_over(url):
    try:
        page = res.get(url)
        soup = BeautifulSoup(page.content, "html.parser")

        # Find all <script> tags
        scripts = soup.find_all('script')

        for script in scripts:
            if script.string:  # Check if the script contains inline code
                if re.search(r'onMouseOver', script.string, re.IGNORECASE):
                    return -1 
        return 1 

    except res.RequestException as e:
        print(f"Error fetching URL: {e}")
        return -1  




