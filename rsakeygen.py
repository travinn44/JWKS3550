import os
import time
import jwt
import json
import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#define keys and expiry time 
keys = []
KEY_EXPIRY_SECONDS = 60 * 60

"""encodes bytes to base64 url format """
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

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

    keys.append({
        'kid' : key_id,
        'private_key': private_pem,
        'public_key': public_pem,
        'expiry': expiry
            
    })
    #returns the key_id  private_pem public_pem and the expiry time
    return key_id, private_pem, public_pem, expiry