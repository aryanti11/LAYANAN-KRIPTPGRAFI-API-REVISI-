from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError
from datetime import datetime, timedelta
import secrets, os, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Optional
import hmac
import hashlib

NONCES: dict[str, str] = {}


# JWT Config
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Security Service", version="1.0.0")
security = HTTPBearer()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Users DB
USERS = {
    "aisyah":"12345678",
    "indah":"87654321",
    "intan":"123456789",
    "sabrina":"987654321"
}

class RelayData(BaseModel):
    sender: str
    receiver: str
    ciphertext: str
    nonce: str

NONCES: dict[str, str] = {}


@app.get("/login/nonce")
async def get_nonce(username: str):
    if username not in USERS:
        raise HTTPException(status_code=404, detail="User not found")

    nonce = secrets.token_hex(16)
    NONCES[username] = nonce

    return {
        "username": username,
        "nonce": nonce
    }


class LoginNonceRequest(BaseModel):
    username: str
    hmac: str


class HmacRequest(BaseModel):
    username: str
    nonce: str

class HmacResponse(BaseModel):
    username: str
    nonce: str
    hmac: str

@app.post("/hmac", response_model=HmacResponse)
async def get_hmac(body: HmacRequest):
    username = body.username
    nonce = body.nonce

    if username not in USERS:
        raise HTTPException(status_code=401, detail="Invalid user")

    password = USERS[username].encode()

    hmac_bytes = hmac.new(
        password,
        nonce.encode(),
        hashlib.sha256
    ).digest()
    hmac_b64 = base64.b64encode(hmac_bytes).decode()

    return HmacResponse(
        username=username,
        nonce=nonce,
        hmac=hmac_b64
    )

@app.post("/login/hmac")
async def login_hmac(body: LoginNonceRequest):
    username = body.username

    if username not in USERS:
        raise HTTPException(status_code=401, detail="Invalid user")

    if username not in NONCES:
        raise HTTPException(status_code=400, detail="Nonce not requested")

    nonce = NONCES.pop(username)
    password = USERS[username].encode()

    expected_hmac = hmac.new(
        password,
        nonce.encode(),
        hashlib.sha256
    ).digest()
    expected_b64 = base64.b64encode(expected_hmac).decode()

    if not hmac.compare_digest(expected_b64, body.hmac):
        raise HTTPException(status_code=401, detail="Invalid HMAC")

    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer"
    }

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.get("/health")
async def health_check():
    return {"status": "Security Service is running", "timestamp": datetime.now().isoformat()}

@app.get("/")
async def get_index():
    return {"message": "Hello world! Please visit http://localhost:8080/docs for API UI."}

os.makedirs("keys", exist_ok=True)

@app.post("/store")
async def store_pubkey(
    username: str,
    pubkey: UploadFile = File(...),
    current_user: str = Depends(verify_token)
):
    if current_user != username:
        raise HTTPException(status_code=403, detail="Unauthorized")

    key_bytes = await pubkey.read()
    if b"PUBLIC KEY" not in key_bytes:
        raise HTTPException(status_code=400, detail="Invalid public key format")

    save_path = f"keys/{username}.pub"
    with open(save_path, "wb") as f:
        f.write(key_bytes)

    return {
        "message": "Public key stored",
        "username": username,
        "path": save_path
    }

@app.post("/verify")
async def verify(
    username: str = Query(...),
    message: str = Query(...),
    signature: str = Query(...),
    current_user: str = Depends(verify_token)
):
    key_path = f"keys/{username}.pub"
    if not os.path.exists(key_path):
        raise HTTPException(status_code=400, detail="Public key not found")

    try:
        with open(key_path, "rb") as f:
            pubkey = serialization.load_pem_public_key(f.read())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key: {str(e)}")
    
    try:
        padding_needed = (4 - len(signature) % 4) % 4
        signature_padded = signature + '=' * padding_needed
        signature_bytes = base64.b64decode(signature_padded)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid signature format: {str(e)}")

    try:
        pubkey.verify(signature_bytes, message.encode(), ec.ECDSA(hashes.SHA256()))
        valid_original = True
    except Exception:
        valid_original = False

    tampered = message + "_X"
    try:
        pubkey.verify(signature_bytes, tampered.encode(), ec.ECDSA(hashes.SHA256()))
        valid_tampered = True
    except Exception:
        valid_tampered = False

    return {
        "username": username,
        "original_message_valid": valid_original,
        "tampered_message_valid": valid_tampered,
        "tampered_message_used": tampered
    }

os.makedirs("messages", exist_ok=True)

@app.post("/relay")
async def relay(data: RelayData, current_user: str = Depends(verify_token)):
    if current_user != data.sender:
        raise HTTPException(status_code=403, detail="Unauthorized")

    save_path = f"messages/{data.receiver}.txt"
    with open(save_path, "a") as f:
        f.write(f"From: {data.sender}\n")
        f.write(f"Ciphertext: {data.ciphertext}\n")
        f.write(f"Nonce: {data.nonce}\n")
        f.write(f"Timestamp: {datetime.now()}\n")
        f.write("-" * 40 + "\n")

    return {
        "message": "Encrypted message relayed successfully",
        "sender": data.sender,
        "receiver": data.receiver,
        "saved_to": save_path
    }

@app.get("/protected")
async def protected(current_user: str = Depends(verify_token)):
    return {"message": "Protected endpoint OK", "user": current_user}

@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...), current_user: str = Depends(verify_token)):
    contents = await file.read()
    with open("secret_message.pdf", "wb") as f:
        f.write(contents)
    return {
        "message": "File uploaded!",
        "content-type": file.content_type,
        "user": current_user
    }

@app.post("/sign-pdf")
async def sign_pdf(file: UploadFile = File(...), current_user: str = Depends(verify_token)):
    pdf_bytes = await file.read()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_bytes)
    pdf_hash = digest.finalize()

    with open("punkhazard-keys/privkey_196.pem", "rb") as f:
        privkey = serialization.load_pem_private_key(f.read(), password=None)

    signature = privkey.sign(pdf_hash, ec.ECDSA(hashes.SHA256()))
    signature_b64 = base64.b64encode(signature).decode()

    return {
        "message": "PDF signed successfully",
        "signature": signature_b64,
        "user": current_user
    }

@app.post("/verify-pdf")
async def verify_pdf(
    file: UploadFile = File(...),
    signature: str = Query(""),
    current_user: str = Depends(verify_token)
):
    pdf_bytes = await file.read()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_bytes)
    pdf_hash = digest.finalize()

    with open("punkhazard-keys/pubkey_196.pem", "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())

    signature_bytes = base64.b64decode(signature + '=' * ((4 - len(signature) % 4) % 4))

    try:
        pubkey.verify(signature_bytes, pdf_hash, ec.ECDSA(hashes.SHA256()))
        return {"valid": True, "message": "PDF signature valid", "user": current_user}
    except Exception:
        return {"valid": False, "message": "PDF signature INVALID"}