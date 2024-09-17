from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello, Flask!'

@app.route('/profile', methods=['POST'])
def create_profile():
    data = request.json
    # Here you would typically validate and save the data to your database
    return jsonify({'message': 'Profile created', 'data': data}), 201

if __name__ == '__main__':
    app.run(debug=True)
