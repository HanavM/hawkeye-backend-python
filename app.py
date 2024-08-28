from flask import Flask
from azure.identity import DefaultAzureCredential
import pyodbc
import urllib

app = Flask(__name__)

# SQL Server details
server = 'hawkeye-server-test.database.windows.net'
database = 'hawkeye-DB-test'
driver = 'ODBC Driver 17 for SQL Server'  # Notice there is no '+' sign

# Build the connection string
params = urllib.parse.quote_plus(f'DRIVER={{{driver}}};SERVER={server};DATABASE={database};Authentication=ActiveDirectoryMSI;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;')

# Connection string for pyodbc
connection_string = f"mssql+pyodbc:///?odbc_connect={params}"

@app.route('/')
def hello():
    return "Hello, World! test: 5"

@app.route('/create_db')
def create_db():
    try:
        # Attempt to connect to the database
        with pyodbc.connect(connection_string) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")  # Simple query to test connection
            return "Connected successfully!", 200
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
