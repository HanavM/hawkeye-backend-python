from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# Use the SQL connection string from the environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQL_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Optional: to suppress a warning

db = SQLAlchemy(app)

# Define a simple UserProfile model for demonstration purposes
class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

# Existing routes (e.g., /profiles) go here

# Simple test route
@app.route('/test')
def test():
    return 'Test route is working!'

if __name__ == '__main__':
    app.run(debug=True)
