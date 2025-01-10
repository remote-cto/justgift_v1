from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_bcrypt import Bcrypt
import openai
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB setup
app.config["MONGO_URI"] = "mongodb://localhost:27017/gifting_db"
client = MongoClient(app.config["MONGO_URI"])
db = client.get_database()

# JWT setup
app.config["JWT_SECRET_KEY"] = "9a2f5a56b3b20c6b8c6a5c91f7e9f1bb"
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# OpenAI API key
openai.api_key = ""  # Use your actual OpenAI API key

@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    # Check if the email already exists
    if db.users.find_one({"email": data["email"]}):
        return jsonify({"message": "Email already exists"}), 400

    # Hash the password before saving to DB
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    db.users.insert_one({'email': data['email'], 'password': hashed_password})
    return jsonify({"message": "User created successfully"}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = db.users.find_one({'email': data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        # Create JWT token upon successful login
        access_token = create_access_token(identity=data['email'])
        return jsonify({"token": access_token}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/gpt', methods=['POST'])
@jwt_required()
def gpt():
    data = request.get_json()
    persona = data.get('persona')

    if not persona:
        return jsonify({"message": "Persona input is required"}), 400

    # Create the prompt for the OpenAI API
    prompt = f"Generate gift keywords for the persona: {persona}"

    try:
        # Use the new API syntax
        response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
        {"role": "system", "content": "You are a helpful assistant that generates gift keywords."},
        {"role": "user", "content": prompt}
    ]
    )
    #Ensure you directly access the response attributes
        keywords_response = response.choices[0].message.content

        keywords = [keyword.strip() for keyword in keywords_response.split(',')]
        return jsonify({"keywords": keywords}), 200

    except openai.OpenAIError as e:
        # Handle OpenAI-specific errors
        return jsonify({"message": f"Error generating keywords: {str(e)}"}), 500

    except Exception as e:
        # Handle other generic errors
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/search', methods=['GET'])
@jwt_required()
def search():
    keywords = request.args.get('keywords')

    if not keywords:
        return jsonify({"message": "Keywords are required for search"}), 400

    keywords = keywords.split(',')
    # Query MongoDB for gift links that match the keywords
    results = db.giftlinks.find({"keyword": {"$in": keywords}})

    gift_list = [{"keyword": gift["keyword"], "link": gift["link"], "description": gift["description"]} for gift in results]
    return jsonify(gift_list), 200

@app.route('/add_gift_link', methods=['POST'])
def add_gift_link():
    gift_data = request.get_json()
    # Check for missing fields
    if not gift_data.get('keyword') or not gift_data.get('link') or not gift_data.get('description'):
        return jsonify({"message": "Missing required fields (keyword, link, description)"}), 400

    # Insert gift link into the MongoDB database
    db.giftlinks.insert_one(gift_data)
    return jsonify({"message": "Gift link added successfully!"}), 201

if __name__ == '__main__':
    app.run(debug=True)
