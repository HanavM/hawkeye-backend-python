import pyodbc

# SQL Server details
server = 'hawkeye-server-test.database.windows.net'
database = 'hawkeye-DB-test'
driver = 'ODBC Driver 17 for SQL Server'

# Build the connection string using Managed Identity
connection_string = (
    f"DRIVER={{{driver}}};"
    f"SERVER={server};"
    f"DATABASE={database};"
    "Authentication=ActiveDirectoryMSI;"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
)

try:
    connection = pyodbc.connect(connection_string)
    print("Connected successfully!")
except Exception as e:
    print(f"Error: {e}")
