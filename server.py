import os
import time
import jwt
import json
import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from rsakeygen import generate_rsa_pair,base64url_encode, keys

app = Flask(__name__)
PORT = 8080



def get_active_keys():
    return [key for key in keys if key['expiry'] > time.time()]

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    active_keys = get_active_keys()
    jwks_keys = []
    for key in active_keys:
        public_key = serialization.load_pem_public_key(key['public_key'], backend=default_backend())
        public_numbers = public_key.public_numbers()
        
        jwks_keys.append({
            'kty': 'RSA',
            'kid': key['kid'],
            'use': 'sig',
            'n': base64url_encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')),
            'e': base64url_encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big'))
        })
    return jsonify({'keys': jwks_keys})


@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired',default=False,type=bool)

    if expired:
        expired_key = next((key for key in keys if key['expiry'] <= time.time()), None)
        if not expired_key:
            return jsonify({"error": "No expired keys available"}), 400
        key= expired_key
    else:
        active_keys = get_active_keys()
        if not active_keys:
            return jsonify({"error":"No active keys available"}), 400
        key = active_keys[-1]

    payload = {
        'sub': 'user_id',
        'iat': int(time.time()),
        'exp': key['expiry']
    }

    headers ={
        'kid' : key['kid']
    }

    token = jwt.encode(payload,key['private_key'],algorithm='RS256',headers=headers)

    return jsonify({'token': token})

if __name__ =='__main__':
    generate_rsa_pair(expired=True)
    generate_rsa_pair(expired=False)

    app.run(port=PORT)