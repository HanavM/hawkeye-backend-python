import instaloader

def get_full_name_instagram(username):
    L = instaloader.Instaloader()
    try:
        # Load the session cookie file (ensure the path and filename are correct)
        L.load_session_from_file('hawkeyeapp_official', '/Users/hanavmodasiya/Downloads/hawkeye-backend/sessionfile.json')
        
        # Load the profile from the username
        profile = instaloader.Profile.from_username(L.context, username)
        
        # Extract full name and split into first and last name
        full_name = profile.full_name.strip()
        name_parts = full_name.split(' ', 1)
        
        if len(name_parts) > 1:
            first_name, last_name = name_parts
        else:
            first_name, last_name = name_parts[0], ''
        
        return first_name, last_name, None
    except instaloader.exceptions.ProfileNotExistsException:
        return None, None, "Error: Username not found."
    except instaloader.exceptions.ConnectionException:
        return None, None, "Error: Unable to connect to Instagram. Please try again later."
    except Exception as e:
        return None, None, f"Error: An unexpected error occurred - {str(e)}"

def get_full_name(username):
    L = instaloader.Instaloader()

    # Set the proxy without authentication (IP only)
    L.context.proxy = "http://161.97.136.251:3128"

    try:
        # Load the profile from the username using the proxy
        profile = instaloader.Profile.from_username(L.context, username)
        
        # Extract full name and split into first and last name
        full_name = profile.full_name.strip()
        name_parts = full_name.split(' ', 1)
        
        if len(name_parts) > 1:
            first_name, last_name = name_parts
        else:
            first_name, last_name = name_parts[0], ''
        
        return first_name, last_name, None  # No error
    except instaloader.exceptions.ProfileNotExistsException:
        return None, None, "Error: Username not found."
    except instaloader.exceptions.ConnectionException:
        return None, None, "Error: Unable to connect to Instagram. Please try again later."
    except Exception as e:
        return None, None, f"Error: An unexpected error occurred - {str(e)}"


def get_full_name_instagram_2(username, proxy):
    """Fetches the full name from Instagram using a proxy and session"""
    L = instaloader.Instaloader()

    # Set the proxy for the Instaloader instance
    L.context.proxy = proxy

    try:
        # Download and load the session file
        L.load_session_from_file('hawkeyeapp_official', '/Users/hanavmodasiya/Downloads/hawkeye-backend/sessionfile')

        # Fetch the Instagram profile data
        profile = instaloader.Profile.from_username(L.context, username)
        
        # Extract and split the full name
        full_name = profile.full_name.strip()
        name_parts = full_name.split(' ', 1)
        
        # Split first and last name or assign blank if missing
        if len(name_parts) > 1:
            first_name, last_name = name_parts
        else:
            first_name, last_name = name_parts[0], ''
        
        return first_name, last_name, None  # No error
    except instaloader.exceptions.ProfileNotExistsException:
        return None, None, "Error: Username not found."
    except instaloader.exceptions.ConnectionException:
        return None, None, "Error: Unable to connect to Instagram. Please try again later."
    except Exception as e:
        return None, None, f"Error: An unexpected error occurred - {str(e)}"



while True:
    username = input("Enter Instagram username: ")
    if (username == "x"): 
        break
    first_name, last_name, error = get_full_name_instagram_2(username, "http://180.112.181.74:8089")

    print(first_name, last_name, error)


    if error:
        print("is an error")
    else:
        print("is not an error")
        print(f"First Name: '{first_name}'")
        print(f"Last Name: '{last_name}'")