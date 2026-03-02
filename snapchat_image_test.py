import html
import requests
from bs4 import BeautifulSoup

def get_display_name(username):
    # Construct the Snapchat profile URL using the username
    url = f"https://www.snapchat.com/add/{username}"

    # Headers to mimic a browser request
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }

    # Sending the request
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        # print(soup)
        # Try to extract the display name using h1
        display_name = soup.select_one("h1")
        
        # Fallback to .Heading_h400Emphasis__SQXxl span if h1 is not found
        if not display_name:
            display_name = soup.select_one(".Heading_h400Emphasis__SQXxl span")
        
        bitmoji_url = soup.select_one(".UserCard_verticalSnapcode__XWFrV")
        bitmoji_url = bitmoji_url.find("img")

        if bitmoji_url and bitmoji_url.has_attr("src"):
            raw_url = bitmoji_url["src"]
            clean_url = html.unescape(raw_url)
            print(clean_url)
        # print(bitmoji_url, type(bitmoji_url))
        # bitmoji_url = bitmoji_url.replace("amp;", "")
        # print(bitmoji_url)

        if display_name:
            # Get the text and split into first and last name
            full_name = display_name.get_text().strip()
            name_parts = full_name.split(" ", 1)  # Split into two parts: first name and last name
            
            first_name = name_parts[0]  # First part is the first name
            last_name = name_parts[1] if len(name_parts) > 1 else ""  # Second part if exists is the last name
            
            return first_name, last_name
        else:
            return None, None
    else:
        return None, None
    


print(get_display_name("johnsonn123"))