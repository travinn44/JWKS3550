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
from argon2 import PasswordHasher
from collections import defaultdict
import time
from cryptography.hazmat.primitives import serialization
import uuid

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
#endpoint that puts user information into a table to store usernames and passwords
@app.route('/register',methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = str(uuid.uuid4())
    ph = PasswordHasher()
    conn = db_connect()
    curs = conn.cursor()
    try:
        pw_hash = ph.hash(password)
        curs.execute("""INSERT INTO users (username, email, password_hash) 
            VALUES (?, ?, ?)""", (username, email, pw_hash))
        conn.commit()
        return jsonify({'password': password}),201
    except:
        return jsonify({"error": "Username or email already exists"}), 400
    finally:
        conn.close()


req_time = defaultdict(list)
#funciton to check how many requests the users is making and stopping if it exceeds the limit
def rate_limiter(uid):
    curr_time = time.time()
    req_time[uid] = [timestamp for timestamp in req_time[uid] if curr_time - timestamp < 1]  # 1 second window
    if len(req_time[uid]) >= 10:  # 10 requests per second
        return True
    req_time[uid].append(curr_time)
    return False

#endpoint verifying user identity and logging users ip and user id when 
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', default=False, type=bool)
    conn = db_connect()
    curs = conn.cursor()
    """if expired:
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
    expiry = key_row['exp']"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    curs.execute("SELECT id, password_hash FROM users WHERE username = ?",(username,))
    user = curs.fetchone()
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401
    user_id = user[0]
    if rate_limiter(user_id):
        return jsonify({"error": "Too many requests, please try again later"}), 429
    user_id, pass_hash = user
    ph =PasswordHasher()
    try:
        ph.verify(pass_hash, password)
    except:
        return jsonify({"error": "Invalid username or password"}), 401   
    ip_address = request.remote_addr
    curs.execute("""
        INSERT INTO auth_logs (request_ip, request_timestamp, user_id)
        VALUES (?, datetime('now'), ?)""", (ip_address, user_id))
    conn.commit()
    return jsonify({"message": "Authentication successful"}), 200
    """payload = {
        'sub': 'user_id',
        'iat': int(time.time()),
        'exp': expiry
    }

    headers = {
        'kid': str(key_row['kid'])
    }

    token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
    return jsonify({'token': token})"""

# Start the server and initialize the database
if __name__ == '__main__':
    conn = db_connect()
    curs = conn.cursor()
    curs.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
    curs.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
    curs.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )""")
    conn.commit()
    conn.close()
   # Generate one expired key and one valid key
    generate_rsa_pair(expired=True)
    generate_rsa_pair(expired=False)

    app.run(port=PORT, debug=True)
 
