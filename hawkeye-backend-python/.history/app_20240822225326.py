import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

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

# Routes for CRUD operations on UserProfile
@app.route('/profiles', methods=['POST'])
def create_profile():
    data = request.json
    new_profile = UserProfile(username=data['username'], email=data['email'])
    db.session.add(new_profile)
    db.session.commit()
    return jsonify({'message': 'Profile created', 'profile': {'id': new_profile.id, 'username': new_profile.username, 'email': new_profile.email}}), 201

@app.route('/profiles', methods=['GET'])
def get_profiles():
    profiles = UserProfile.query.all()
    return jsonify([{'id': p.id, 'username': p.username, 'email': p.email} for p in profiles])

if __name__ == '__main__':
    app.run(debug=True)
