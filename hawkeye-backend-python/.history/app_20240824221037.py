from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# Configure the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://HanavM:password@hawkeye-server-test.database.windows.net:1433/hawkeye-DB-test?driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Define a simple User model for demonstration
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

@app.route('/')
def hello():
    return "Hello, World! test:3"

# Endpoint to create the database tables

@app.route('/create_db', methods=['GET'])
def create_db():
    try:
        # Assuming db is already defined with SQLAlchemy
        db.create_all()
        return "Database tables created successfully!", 200
    except Exception as e:
        return str(e), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

