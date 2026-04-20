from __future__ import annotations

import base64
import json
import secrets
import time
import uuid
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DOCUMENTS_DIR = DATA_DIR / "documents"
METADATA_FILE = DATA_DIR / "document_metadata.json"
CERTS_DIR = BASE_DIR / "certs"
USER_PUBLIC_KEYS_DIR = BASE_DIR / "userpublickeys"

SERVER_PRIVATE_KEY_FILE = CERTS_DIR / "secure-shared-store.key"
SERVER_PUBLIC_KEY_FILE = CERTS_DIR / "secure-shared-store.pub"

DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

if not METADATA_FILE.exists():
    METADATA_FILE.write_text("{}", encoding="utf-8")

# Demo-only in-memory session storage
user_sessions: dict[str, str] = {}


def load_metadata() -> dict[str, Any]:
    with METADATA_FILE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_metadata(metadata: dict[str, Any]) -> None:
    with METADATA_FILE.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)


def get_user_from_token(token: str) -> str | None:
    return next((user for user, session_token in user_sessions.items() if session_token == token), None)


def encrypt_with_aes_key(plaintext: bytes, key: bytes) -> bytes:
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext


def decrypt_with_aes_key(ciphertext: bytes, key: bytes) -> bytes:
    iv = ciphertext[:16]
    encrypted_body = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_body) + decryptor.finalize()


def encrypt_key_with_rsa(aes_key: bytes) -> bytes:
    with SERVER_PUBLIC_KEY_FILE.open("rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())

    return public_key.encrypt(aes_key, padding.PKCS1v15())


def decrypt_key_with_rsa(encrypted_key: bytes) -> bytes:
    with SERVER_PRIVATE_KEY_FILE.open("rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    return private_key.decrypt(encrypted_key, padding.PKCS1v15())


def sign_data(data: bytes) -> bytes:
    with SERVER_PRIVATE_KEY_FILE.open("rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify_server_signature(data: bytes, signature: bytes) -> bool:
    with SERVER_PUBLIC_KEY_FILE.open("rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())

    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def verify_login_statement(statement: str, signed_statement: bytes, user_public_key_file: Path) -> bool:
    if not user_public_key_file.exists():
        return False

    with user_public_key_file.open("rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())

    try:
        public_key.verify(
            signed_statement,
            statement.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def is_authorized(user: str, doc_meta: dict[str, Any], action_type: int) -> bool:
    """
    action_type:
      1 = checkin
      2 = checkout
      3 = both
    """
    if user == doc_meta.get("owner"):
        return True

    grants = doc_meta.get("grants", {})
    now = int(time.time())

    if user in grants:
        grant = grants[user]
        if now < grant["expiry"] and (grant["access_right"] == action_type or grant["access_right"] == 3):
            return True

    if "0" in grants:
        grant = grants["0"]
        if now < grant["expiry"] and (grant["access_right"] == action_type or grant["access_right"] == 3):
            return True

    return False


@app.get("/")
def welcome():
    return "Welcome to the Secure Shared Store service."


@app.post("/login")
def login():
    data = request.get_json(force=True)
    user_id = data["user-id"]
    statement = data["statement"]
    signed_statement = base64.b64decode(data["signed-statement"])

    user_public_key_file = USER_PUBLIC_KEYS_DIR / f"{user_id}.pub"
    success = verify_login_statement(statement, signed_statement, user_public_key_file)

    if not success:
        return jsonify(
            {
                "status": 700,
                "message": "Login failed",
                "session_token": "INVALID",
            }
        )

    session_token = str(uuid.uuid4())
    user_sessions[user_id] = session_token

    return jsonify(
        {
            "status": 200,
            "message": "Login successful",
            "session_token": session_token,
        }
    )


@app.post("/checkin")
def checkin():
    """
    Status codes:
      200 = success
      702 = access denied
      700 = other failures
    """
    data = request.get_json(force=True)
    token = data["token"]
    filename = data["filename"]
    file_data = base64.b64decode(data["file_data"])
    security_flag = int(data["security_flag"])

    user_id = get_user_from_token(token)
    if user_id is None:
        return jsonify({"status": 702, "message": "Access denied checking in"})

    metadata = load_metadata()
    doc_meta = metadata.get(filename, {})

    if not doc_meta:
        doc_meta = {"owner": user_id, "grants": {}}
    elif not is_authorized(user_id, doc_meta, action_type=1):
        return jsonify({"status": 702, "message": "Access denied checking in"})

    file_path = DOCUMENTS_DIR / filename

    try:
        if security_flag == 1:
            aes_key = secrets.token_bytes(32)
            encrypted_data = encrypt_with_aes_key(file_data, aes_key)
            encrypted_key = encrypt_key_with_rsa(aes_key)

            file_path.write_bytes(encrypted_data)
            doc_meta.update(
                {
                    "security_flag": 1,
                    "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
                    "signature": "",
                }
            )
        elif security_flag == 2:
            signature = sign_data(file_data)

            file_path.write_bytes(file_data)
            doc_meta.update(
                {
                    "security_flag": 2,
                    "signature": base64.b64encode(signature).decode("utf-8"),
                    "encrypted_key": "",
                }
            )
        else:
            raise ValueError("security_flag must be 1 (confidentiality) or 2 (integrity)")

        metadata[filename] = doc_meta
        save_metadata(metadata)

        return jsonify({"status": 200, "message": "Document successfully checked in"})
    except Exception as exc:
        return jsonify({"status": 700, "message": f"Checkin failed: {exc}"})


@app.post("/checkout")
def checkout():
    """
    Status codes:
      200 = success
      702 = access denied
      703 = integrity failure
      704 = not found
      700 = other failures
    """
    data = request.get_json(force=True)
    token = data["token"]
    filename = data["filename"]

    user_id = get_user_from_token(token)
    if user_id is None:
        return jsonify(
            {
                "status": 702,
                "message": "Access denied checking out",
                "file": "Invalid",
            }
        )

    try:
        metadata = load_metadata()
        if filename not in metadata:
            return jsonify(
                {
                    "status": 704,
                    "message": "File not found on the server",
                    "file": "Invalid",
                }
            )

        doc_meta = metadata[filename]
        file_path = DOCUMENTS_DIR / filename

        if not file_path.exists():
            return jsonify(
                {
                    "status": 704,
                    "message": "File not found on the server",
                    "file": "Invalid",
                }
            )

        if not is_authorized(user_id, doc_meta, action_type=2):
            return jsonify(
                {
                    "status": 702,
                    "message": "Access denied checking out",
                    "file": "Invalid",
                }
            )

        file_data = file_path.read_bytes()

        if doc_meta["security_flag"] == 1:
            encrypted_key = base64.b64decode(doc_meta["encrypted_key"])
            aes_key = decrypt_key_with_rsa(encrypted_key)
            plaintext = decrypt_with_aes_key(file_data, aes_key)
        elif doc_meta["security_flag"] == 2:
            signature = base64.b64decode(doc_meta["signature"])
            if not verify_server_signature(file_data, signature):
                return jsonify(
                    {
                        "status": 703,
                        "message": "Checkout failed due to broken integrity",
                        "file": "Invalid",
                    }
                )
            plaintext = file_data
        else:
            return jsonify(
                {
                    "status": 700,
                    "message": "Unknown security flag",
                    "file": "Invalid",
                }
            )

        encoded_file = base64.b64encode(plaintext).decode("utf-8")
        return jsonify(
            {
                "status": 200,
                "message": "Document successfully checked out",
                "file": encoded_file,
            }
        )
    except Exception as exc:
        return jsonify({"status": 700, "message": f"Checkout failed: {exc}", "file": "Invalid"})


@app.post("/grant")
def grant():
    """
    Status codes:
      200 = success
      702 = access denied
      700 = other failures
    """
    data = request.get_json(force=True)
    token = data["token"]
    filename = data["filename"]
    target_user = data["target_user"]
    access_right = int(data["access_right"])
    duration = int(data["duration"])

    user_id = get_user_from_token(token)
    if user_id is None:
        return jsonify({"status": 702, "message": "Access denied to grant access"})

    try:
        metadata = load_metadata()
        if filename not in metadata:
            return jsonify({"status": 700, "message": "Grant failed: file not found"})

        doc_meta = metadata[filename]
        if doc_meta.get("owner") != user_id:
            return jsonify({"status": 702, "message": "Access denied: only owner can grant access"})

        expiry_time = int(time.time()) + duration
        doc_meta.setdefault("grants", {})
        doc_meta["grants"][target_user] = {
            "access_right": access_right,
            "expiry": expiry_time,
        }

        metadata[filename] = doc_meta
        save_metadata(metadata)

        return jsonify(
            {
                "status": 200,
                "message": f"Successfully granted access to {target_user} for {filename}",
            }
        )
    except Exception as exc:
        return jsonify({"status": 700, "message": f"Grant failed: {exc}"})


@app.post("/delete")
def delete():
    """
    Status codes:
      200 = success
      702 = access denied
      704 = not found
      700 = other failures
    """
    data = request.get_json(force=True)
    token = data["token"]
    filename = data["filename"]

    user_id = get_user_from_token(token)
    if user_id is None:
        return jsonify({"status": 702, "message": "Access denied deleting file"})

    try:
        metadata = load_metadata()
        if filename not in metadata:
            return jsonify({"status": 704, "message": "Delete failed: file not found"})

        doc_meta = metadata[filename]
        if doc_meta.get("owner") != user_id:
            return jsonify({"status": 702, "message": "Access denied: only owner can delete"})

        file_path = DOCUMENTS_DIR / filename
        if file_path.exists():
            file_path.unlink()

        metadata.pop(filename, None)
        save_metadata(metadata)

        return jsonify({"status": 200, "message": f"Successfully deleted {filename}"})
    except Exception as exc:
        return jsonify({"status": 700, "message": f"Delete failed: {exc}"})


@app.post("/logout")
def logout():
    data = request.get_json(force=True)
    token = data["token"]

    user_id = get_user_from_token(token)
    if user_id is None or token != user_sessions.get(user_id):
        return jsonify({"status": 700, "message": "Logout failed"})

    user_sessions.pop(user_id, None)
    return jsonify({"status": 200, "message": "Successfully logged out"})


def main():
    app.run(debug=True)


if __name__ == "__main__":
    main()