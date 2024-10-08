from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from azure.identity import DefaultAzureCredential
import urllib

app = Flask(__name__)

# Use DefaultAzureCredential, specifying the user-assigned managed identity
credential = DefaultAzureCredential(managed_identity_client_id="f3b25b77-72be-46c4-b6dd-506f49c55bd9")

# SQL Server details
server = 'hawkeye-server-test.database.windows.net'
database = 'hawkeye-DB-test'
driver = 'ODBC+Driver+17+for+SQL+Server'

# Build the connection string
params = urllib.parse.quote_plus(
    f'DRIVER={{{driver}}};'
    f'SERVER={server};'
    f'DATABASE={database};'
    'Authentication=ActiveDirectoryMSI;'
    'Encrypt=yes;'
    'TrustServerCertificate=no;'
    'Connection Timeout=30;'
)

# Set the SQLALCHEMY_DATABASE_URI configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc:///?odbc_connect={params}"

# Initialize SQLAlchemy
db = SQLAlchemy(app)

@app.route('/')
def hello():
    return "Hello, World! test: 10"

@app.route('/create_db')
def create_db():
    try:
        db.create_all()
        return "Database tables created successfully!", 200
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
