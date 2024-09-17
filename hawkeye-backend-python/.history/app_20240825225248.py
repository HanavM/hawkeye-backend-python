from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from azure.identity import ManagedIdentityCredential
from sqlalchemy.engine import create_engine

app = Flask(__name__)

# Use the Managed Identity to get credentials
credential = ManagedIdentityCredential()

# Connection string with Azure AD authentication using Managed Identity
connection_string = "mssql+pyodbc://@hawkeye-server-test.database.windows.net/hawkeye-DB-test?driver=ODBC+Driver+17+for+SQL+Server&authentication=ActiveDirectoryMSI"

# Set the SQLALCHEMY_DATABASE_URI configuration
app.config['SQLALCHEMY_DATABASE_URI'] = connection_string

# Initialize SQLAlchemy
db = SQLAlchemy(app)

@app.route('/')
def hello():
    return "Hello, World!"

@app.route('/create_db')
def create_db():
    try:
        db.create_all()
        return "Database tables created successfully!", 200
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
