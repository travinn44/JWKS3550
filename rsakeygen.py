import os
import time
import jwt
import json
import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import sqlite3

#define keys and expiry time 
keys = []
KEY_EXPIRY_SECONDS = 60 * 60
DB_PATH = "C:/Users/rutol/OneDrive/Desktop/jwksserver/totally_not_my_privateKeys.db"

"""function that conncects to the database allowing it to be manipulated"""
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
"""function to encrypt and return the key after it has been encrypted using AES"""
def encrypt_key(key,text):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    paddedData = padder.update(text) + padder.finalize()
    encrypted = encryptor.update(paddedData) + encryptor.finalize()
    return iv + encrypted 

"""fuction inserts a generated key into the database"""
def save_keys(private_key_pem, expiry):
    key = os.getenv("NOT_MY_KEY","1234567890abcdef").encode()
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes.")
    encryptedkey = encrypt_key(key,private_key_pem)
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key,exp) VALUES (?, ?)",(encryptedkey,expiry))
    conn.commit()
    conn.close()

"""encodes bytes to base64 url format """
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

"""these two functions access the database and retrives either a active key or a expired key"""
def get_active_keys():
    conn = db_connect()
    cursor = conn.cursor()
    current_time = int(time.time())
    cursor.execute("Select * FROM keys WHERE exp > ?", (current_time,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_expired_keys():
    conn = db_connect()
    cursor = conn.cursor()
    current_time = int(time.time())
    cursor.execute("SELECT * FROM keys WHERE exp <= ?", (current_time,))
    row = cursor.fetchone()
    conn.close()
    return row

"""
this function generates public and private keys 
using a boolean it determines if the key is expired or not 
appends the created keys into the keys array that gets carried over to the main file of the program 
"""
def generate_rsa_pair(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
     
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding= serialization.Encoding.PEM,
        format=  serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm= serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_id = os.urandom(16).hex()  # Generate a unique Key ID
    expiry = int(time.time()) + (KEY_EXPIRY_SECONDS if not expired else -1)

    save_keys(private_pem,expiry)

    keys.append({
        'kid' : key_id,
        'private_key': private_pem,
        'public_key': public_pem,
        'expiry': expiry
            
    })
    #returns the key_id  private_pem public_pem and the expiry time
    return key_id, private_pem, public_pem, expiry