# File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API

import os
import json
import base64
import hmac
import hashlib
from urllib import request, parse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER = "http://localhost:8080/docs"

PRIV = "punkhazard-keys/privkey_196.pem"
PUB  = "punkhazard-keys/pubkey_196.pem"

def generate_keys():
    
    os.makedirs("punkhazard-keys", exist_ok=True)

    if os.path.exists(PRIV) and os.path.exists(PUB):
        print("Keys exist")
        return

    priv = ec.generate_private_key(ec.SECP256R1())
    priv_bytes = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    open(PRIV, "wb").write(priv_bytes)

    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    open(PUB, "wb").write(pub_bytes)

    print("New EC keys generated")

    if os.path.exists(PRIV) and os.path.exists(PUB):
        print("Keys exist")
        return

    priv = ec.generate_private_key(ec.SECP256R1())
    priv_bytes = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    open(PRIV, "wb").write(priv_bytes)

    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    open(PUB, "wb").write(pub_bytes)

    print("New EC keys generated")

def login_with_nonce(username, password):
    nonce_url = f"{SERVER}/login/nonce?username={username}"
    resp = request.urlopen(nonce_url)
    nonce = json.loads(resp.read().decode())["nonce"]

    print("[LOGIN] Nonce:", nonce)

    hmac_value = hmac.new(
        password.encode(),
        nonce.encode(),
        hashlib.sha256
    ).digest()

    hmac_b64 = base64.b64encode(hmac_value).decode()

    payload = {
        "username": username,
        "hmac": hmac_b64
    }

    data = json.dumps(payload).encode("utf-8")

    req = request.Request(
        f"{SERVER}/login",
        data=data,
        method="POST"
    )
    req.add_header("Content-Type", "application/json")

    try:
        resp = request.urlopen(req)
        result = json.loads(resp.read().decode())
        print("[LOGIN] Success")
        return result["access_token"]

    except Exception as e:
        if hasattr(e, "read"):
            print("[LOGIN ERROR]", e.read().decode())
        else:
            print("[LOGIN ERROR]", e)
        raise


def sign_message(message):
    priv = serialization.load_pem_private_key(open(PRIV, "rb").read(), None)
    signature = priv.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode()

def encrypt_message(msg: str):
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, msg.encode(), None)

    return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode(), key

# def relay(sender, receiver, ciphertext, nonce):
#     payload = {
#         "sender": sender,
#         "receiver": receiver,
#         "ciphertext": ciphertext,
#         "nonce": nonce
#     }

#     data = json.dumps(payload).encode("utf-8")

#     req = request.Request(
#         f"{SERVER}/relay",
#         data=data,
#         method="POST"
#     )
#     req.add_header("Content-Type", "application/json")

#     resp = request.urlopen(req)
#     print("[RELAY]", resp.read().decode())

def login_with_nonce(username, password):
    resp = request.urlopen(
        f"{SERVER}/login/nonce?username={username}"
    )
    nonce = json.loads(resp.read().decode())["nonce"]

    print("NONCE SERVER :", nonce)

    hmac_bytes = hmac.new(
        password.encode("utf-8"),
        nonce.encode("utf-8"),
        hashlib.sha256
    ).digest()

    hmac_b64 = base64.b64encode(hmac_bytes).decode()

    print("HMAC CLIENT :", hmac_b64)

    payload = {
        "username": username,
        "hmac": hmac_b64
    }

    data = json.dumps(payload).encode("utf-8")

    req = request.Request(
        f"{SERVER}/login",
        data=data,
        method="POST"
    )
    req.add_header("Content-Type", "application/json")

    resp = request.urlopen(req)
    result = json.loads(resp.read().decode())

    return result["access_token"]


    # print("[LOGIN] Success")
    # return result["access_token"]

def relay(sender, receiver, ciphertext, nonce, token):
    payload = {
        "sender": sender,
        "receiver": receiver,
        "ciphertext": ciphertext,
        "nonce": nonce
    }

    data = json.dumps(payload).encode("utf-8")

    req = request.Request(
        f"{SERVER}/relay",
        data=data,
        method="POST"
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")

    resp = request.urlopen(req)
    print("[RELAY]", resp.read().decode())


if __name__ == "__main__":

    generate_keys()

    message = "Halo Aryanti, Intan, Sabrina"
    signature_b64 = sign_message(message)

    print("Public key   :", PUB)
    print("Private key  :", PRIV)
    print("Message      :", message)
    print("Signature    :", signature_b64)

    ciphertext, nonce, aeskey = encrypt_message(
        "ini pesan rahasia dari Aisyah"
    )

    print("Ciphertext   :", ciphertext)
    print("Nonce        :", nonce)