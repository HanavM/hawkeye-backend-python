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
        
        # Try to extract the display name using h1
        display_name = soup.select_one("h1")
        
        # Fallback to .Heading_h400Emphasis__SQXxl span if h1 is not found
        if not display_name:
            display_name = soup.select_one(".Heading_h400Emphasis__SQXxl span")
        
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

# Example usage
username = input("Enter Snapchat username: ")
first_name, last_name = get_display_name(username)

print(first_name == None, last_name == "")

# if first_name:
#     print(f"First Name: {first_name}")
#     if last_name:
#         print(f"Last Name: {last_name}")
# else:
#     print("Display name not found.")
