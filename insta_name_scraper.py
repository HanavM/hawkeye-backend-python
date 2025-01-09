import instaloader

def get_full_name_instagram(username):
    L = instaloader.Instaloader()
    try:
        # Load the locally saved session file
        L.load_session_from_file('hawkeyeapp_official', '/Users/hanavmodasiya/.config/instaloader/session-hawkeyeapp_official')
        
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
        return None, None, f"Error: An unexpected error occurred - {str(e)}"

# # Example usage
# if __name__ == "__main__":
#     username = input("Enter Instagram username: ")
#     first_name, last_name, error = get_full_name(username)
    
#     if error:
#         print(error)
#     else:
#         print(f"First Name: {first_name}")
#         print(f"Last Name: {last_name}")

while True:
    username = input("Enter Instagram username: ")
    if (username == "x"): 
        break
    first_name, last_name, error = get_full_name_instagram(username)

    print(first_name, last_name, error)


    if error:
        print("is an error")
    else:
        print("is not an error")
        print(f"First Name: '{first_name}'")
        print(f"Last Name: '{last_name}'")