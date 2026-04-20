from __future__ import annotations

import base64
import json
import os
import shutil
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE_DIR = Path(__file__).resolve().parent
APP_NAME = "secure-shared-store"

CLIENT_ID = os.getenv("CLIENT_ID", BASE_DIR.name)
SERVER_URL = os.getenv("SERVER_URL", "https://localhost:5000")

CERTS_DIR = BASE_DIR / "certs"
USER_KEYS_DIR = BASE_DIR / "userkeys"
DOCUMENTS_DIR = BASE_DIR / "documents"
CHECKIN_DIR = DOCUMENTS_DIR / "checkin"
CHECKOUT_DIR = DOCUMENTS_DIR / "checkout"

NODE_CERTIFICATE = CERTS_DIR / f"{CLIENT_ID}.crt"
NODE_KEY = CERTS_DIR / f"{CLIENT_ID}.key"
CA_CERT = CERTS_DIR / "CA.crt"

CHECKIN_DIR.mkdir(parents=True, exist_ok=True)
CHECKOUT_DIR.mkdir(parents=True, exist_ok=True)


def post_request(action: str, body: dict) -> requests.Response:
    request_url = f"{SERVER_URL}/{action}"
    request_headers = {"Content-Type": "application/json"}

    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(str(NODE_CERTIFICATE), str(NODE_KEY)),
        verify=str(CA_CERT),
        timeout=(10, 20),
    )
    return response


def sign_statement(statement: str, user_private_key_file: Path) -> bytes:
    with user_private_key_file.open("rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    return private_key.sign(statement.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())


def login() -> dict:
    while True:
        user_id = (input("User ID [user1]: ").strip() or "user1")
        private_key_filename = (input("Private key file [user1.key]: ").strip() or "user1.key")
        user_private_key_file = USER_KEYS_DIR / private_key_filename

        if not user_private_key_file.exists():
            print(f"Private key file not found: {user_private_key_file}")
            continue

        statement = f"{CLIENT_ID} as {user_id} logs into the Server"
        signed_statement = sign_statement(statement, user_private_key_file)

        body = {
            "user-id": user_id,
            "statement": statement,
            "signed-statement": base64.b64encode(signed_statement).decode("utf-8"),
        }

        response = post_request("login", body)
        payload = response.json()

        if payload.get("status") == 200:
            print(payload.get("message"))
            return payload

        print(payload.get("message", "Login failed. Please try again."))


def checkin(session_token: str) -> None:
    filename = input("Enter the filename to check in: ").strip()
    security_flag = input("Enter security flag (1 = confidentiality, 2 = integrity): ").strip()

    checkout_path = CHECKOUT_DIR / filename
    checkin_path = CHECKIN_DIR / filename

    if checkout_path.exists():
        print(f"Moving {filename} from checkout to checkin.")
        shutil.move(str(checkout_path), str(checkin_path))
    elif not checkin_path.exists():
        print("File not found in either checkout or checkin directory.")
        return

    with checkin_path.open("rb") as handle:
        file_data = handle.read()

    body = {
        "token": session_token,
        "filename": filename,
        "security_flag": int(security_flag),
        "file_data": base64.b64encode(file_data).decode("utf-8"),
        "client_id": CLIENT_ID,
    }

    response = post_request("checkin", body)
    print(response.json().get("message"))


def checkout(session_token: str) -> None:
    filename = input("Enter the filename to check out: ").strip()

    body = {
        "token": session_token,
        "filename": filename,
        "client_id": CLIENT_ID,
    }

    response = post_request("checkout", body)
    payload = response.json()

    if payload.get("status") != 200:
        print(f"Checkout failed: {payload.get('message')}")
        return

    file_data = base64.b64decode(payload["file"])
    output_path = CHECKOUT_DIR / filename

    with output_path.open("wb") as handle:
        handle.write(file_data)

    print(f"File '{filename}' successfully checked out to {output_path}")


def grant(session_token: str) -> None:
    filename = input("Enter the filename to grant access to: ").strip()
    target_user = input("Enter target user ID (0 for all): ").strip().lower()
    access_right = input("Enter access level (1 = checkin, 2 = checkout, 3 = both): ").strip()
    duration = input("Enter duration in seconds: ").strip()

    try:
        access_right = int(access_right)
        duration = int(duration)
        assert access_right in [1, 2, 3]
        assert duration >= 0
    except Exception:
        print("Invalid access level or duration.")
        return

    body = {
        "token": session_token,
        "filename": filename,
        "target_user": target_user,
        "access_right": access_right,
        "duration": duration,
    }

    response = post_request("grant", body)
    print(response.json().get("message"))


def delete(session_token: str) -> None:
    filename = input("Enter the filename to delete: ").strip()
    body = {"token": session_token, "filename": filename}
    response = post_request("delete", body)
    print(response.json().get("message"))


def logout(session_token: str) -> None:
    remaining_files = list(CHECKOUT_DIR.glob("*"))
    if remaining_files:
        print("\nWarning: You still have files in the checkout directory.")
        print("Check them in manually if you want your latest changes saved before logging out.")
        for file_path in remaining_files:
            print(f" - {file_path.name}")

    body = {"token": session_token}
    response = post_request("logout", body)
    print(response.json().get("message"))


def print_main_menu() -> None:
    print("\nChoose an option:")
    print("  1. Checkin")
    print("  2. Checkout")
    print("  3. Grant")
    print("  4. Delete")
    print("  5. Logout")


def main() -> None:
    login_payload = login()
    session_token = login_payload["session_token"]

    while True:
        print_main_menu()
        user_choice = input("> ").strip()

        if user_choice == "1":
            checkin(session_token)
        elif user_choice == "2":
            checkout(session_token)
        elif user_choice == "3":
            grant(session_token)
        elif user_choice == "4":
            delete(session_token)
        elif user_choice == "5":
            logout(session_token)
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()