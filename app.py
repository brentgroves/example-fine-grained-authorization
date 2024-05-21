from flask import Flask, jsonify, request, g
import os
import jwt
import base64
from auth import token_required
from access_control import authorize_access
import requests


app = Flask(__name__)

ZITADEL_INTROSPECTION_URL = os.getenv('ZITADEL_INTROSPECTION_URL')
API_CLIENT_ID = os.getenv('API_CLIENT_ID')
API_CLIENT_SECRET = os.getenv('API_CLIENT_SECRET')

# Define the /write_article route.
@app.route('/testme', methods=['GET'])
def test():
    token = request.headers.get('Authorization')

    # authorization = authorize_access('review_article')
    if not token:
        abort(401) # Return status code 401 for Unauthorized if there's no token
    else:
        token = token.split(' ')[1] # The token is in the format "Bearer <token>", we want to extract the actual token

    # Call the introspection endpoint
    introspection_response = requests.post(
        ZITADEL_INTROSPECTION_URL,
        auth=(API_CLIENT_ID, API_CLIENT_SECRET),
        data={'token': token}
    )

    if not introspection_response.json().get('active', False):
        return jsonify({"message": "Invalid token"}), 403
    
    
    # Decode the token and print it for inspection
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    print(f"\n\n***** Decoded Token: {decoded_token} \n\n******")

    # Add the decoded token to Flask's global context
    g.token = decoded_token

    # Initialize role and experience_level variables
    role = None
    experience_level = None

    for claim, value in decoded_token.items():
        if ':experience_level' in claim:
            role, _ = claim.split(':')
            experience_level = base64.b64decode(value).decode('utf-8')
            break

# 'journalist:experience_level': 'c2VuaW9y'
    # Resource-specific code goes here...
    return jsonify({"message": "Article written successfully!"}), 200

# Define the /write_article route.
@app.route('/write_article', methods=['POST'])
@token_required
def write_article():
    authorization = authorize_access('write_article')
    if authorization is not True:
        return authorization
    # Resource-specific code goes here...
    return jsonify({"message": "Article written successfully!"}), 200


# Define the /edit_article route.
@app.route('/edit_article', methods=['PUT'])
@token_required
def edit_article():
    authorization = authorize_access('edit_article')
    if authorization is not True:
        return authorization    
    # Resource-specific code goes here...
    return jsonify({"message": "Article edited successfully!"}), 200

# Define the /review_article route.
@app.route('/review_articles', methods=['GET'])
@token_required
def review_article():
    authorization = authorize_access('review_article')
    if authorization is not True:
        return authorization
    # Resource-specific code goes here...
    return jsonify({"message": "Article review accessed successfully!"}), 200

# Define the /publish_article route.
@app.route('/publish_article', methods=['POST'])
@token_required
def publish_article():
    authorization = authorize_access('publish_article')
    if authorization is not True:
        return authorization
    # Resource-specific code goes here...
    return jsonify({"message": "Article published successfully!"}), 200

# Add more endpoints as needed...

if __name__ == '__main__':
    app.run(debug=True)
