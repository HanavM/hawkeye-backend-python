import os
import pyodbc
from flask import Flask
from sqlalchemy import create_engine
import requests

app = Flask(__name__)

# Get the Managed Identity token
token_response = requests.get(
    "http://169.254.169.254/metadata/identity/oauth2/token",
    params={
        "api-version": "2019-08-01",
        "resource": "https://database.windows.net/"
    },
    headers={"Metadata": "true"}
)
access_token = token_response.json()['access_token']

# Connection string with access token
connection_string = (
    "Driver={ODBC Driver 17 for SQL Server};"
    "Server=tcp:hawkeye-server-test.database.windows.net,1433;"
    "Database=hawkeye-DB-test;"
    "Authentication=ActiveDirectoryMsi;"
    f"AccessToken={access_token};"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
)

# Create engine with connection string
engine = create_engine(f"mssql+pyodbc:///?odbc_connect={connection_string}")

@app.route('/')
def hello():
    with engine.connect() as conn:
        result = conn.execute("SELECT @@version")
        return str(result.fetchone())
