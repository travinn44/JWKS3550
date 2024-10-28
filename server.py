import os
import time
import jwt
import json
import base64
import sqlite3
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from rsakeygen import generate_rsa_pair, base64url_encode, get_active_keys, get_expired_keys, db_connect,DB_PATH

#intializing the server on the port 8080
app = Flask(__name__)
PORT = 8080

#endpoint defining and returning an inital JWKS json of the active public keys inside the database 
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    active_keys = get_active_keys()
    jwks_keys = []
    
    for key_row in active_keys:
        private_key_pem = key_row['key']
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        jwks_keys.append({
            'kty': 'RSA',
            'kid': str(key_row['kid']),
            'use': 'sig',
            'n': base64url_encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')),
            'e': base64url_encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big'))
        })
    
    return jsonify({'keys': jwks_keys})

#endpoint defining and returning a JWT of the keys inside the database 
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', default=False, type=bool)

    if expired:
        expired_keys = get_expired_keys()
        if not expired_keys:
            return jsonify({"error": "No expired keys available"}), 400
        key_row = expired_keys[-1]
    else:
        active_keys = get_active_keys()
        if not active_keys:
            return jsonify({"error": "No active keys available"}), 400
        key_row = active_keys[-1]  

    private_key_pem = key_row['key']
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    expiry = key_row['exp']

    payload = {
        'sub': 'user_id',
        'iat': int(time.time()),
        'exp': expiry
    }

    headers = {
        'kid': str(key_row['kid'])
    }

    token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
    
    return jsonify({'token': token})

# Start the server and initialize the database
if __name__ == '__main__':

    # Generate one expired key and one valid key
    generate_rsa_pair(expired=True)
    generate_rsa_pair(expired=False)

    app.run(port=PORT)