import secrets

# Generate a random 64-byte key for the refresh token secret
refresh_secret_key = secrets.token_hex(64)

print(refresh_secret_key)
