import instaloader

L = instaloader.Instaloader()

try:
    # Load the same session file locally
    L.load_session_from_file('hawkeyeapp_official', 'sessionfile')
    print("Session file loaded successfully!")
    
    # Test profile access
    profile = instaloader.Profile.from_username(L.context, 'instagram')
    print("Profile fetched successfully:", profile.full_name)
except Exception as e:
    print(f"Error: {e}")
