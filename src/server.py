import base64
import hashlib
import http.server
import json
import mimetypes
import os
import re
import secrets
import socketserver
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", "3000"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
STORAGE_DIR = os.path.abspath(os.environ.get("STORAGE_DIR", os.path.join(BASE_DIR, "uploads")))
DATA_FILE = os.path.abspath(os.environ.get("DATA_FILE", os.path.join(STORAGE_DIR, "app_state.json")))
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))

key_b64 = os.environ.get("ENCRYPTION_KEY", "")
if not key_b64:
    raise RuntimeError("ENCRYPTION_KEY is required. Generate a 32-byte base64 key for local or production use.")
try:
    ENCRYPTION_KEY = base64.urlsafe_b64decode(key_b64.encode("ascii"))
except Exception as exc:
    raise RuntimeError("ENCRYPTION_KEY must be a URL-safe base64 encoded key.") from exc
if len(ENCRYPTION_KEY) != 32:
    raise RuntimeError("ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).")

os.makedirs(STORAGE_DIR, exist_ok=True)


def utc_now():
    return datetime.now(timezone.utc)


def load_state():
    if not os.path.exists(DATA_FILE):
        return {"users": {}, "sessions": {}, "files": {}}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        return {
            "users": state.get("users", {}),
            "sessions": state.get("sessions", {}),
            "files": state.get("files", {}),
        }
    except (OSError, json.JSONDecodeError):
        return {"users": {}, "sessions": {}, "files": {}}


def save_state(state):
    temp_file = DATA_FILE + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    os.replace(temp_file, DATA_FILE)


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password, encoded):
    try:
        scheme, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def encrypt_bytes(data):
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(ENCRYPTION_KEY).encrypt(nonce, data, None)
    return nonce, ciphertext


def decrypt_bytes(nonce_b64, ciphertext):
    nonce = base64.urlsafe_b64decode(nonce_b64.encode())
    return AESGCM(ENCRYPTION_KEY).decrypt(nonce, ciphertext, None)


def safe_filename(name):
    name = os.path.basename(name).replace("\r", "").replace("\n", "")
    return name[:255] or "download"


def parse_multipart_data(content_type, body):
    match = re.search(r"boundary=([^;]+)", content_type)
    if not match:
        return {}, None
    boundary = match.group(1).strip('"').encode()
    parts = body.split(b"--" + boundary)
    fields, file_info = {}, None

    for part in parts:
        if not part or part in (b"--", b"--\r\n"):
            continue
        part = part.strip(b"\r\n")
        if b"\r\n\r\n" not in part:
            continue
        header_bytes, value = part.split(b"\r\n\r\n", 1)
        headers = header_bytes.decode("utf-8", errors="ignore")
        disposition = re.search(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]*)")?',
            headers,
            re.I,
        )
        if not disposition:
            continue
        field_name, filename = disposition.groups()
        if filename is not None:
            mime_match = re.search(r"Content-Type:\s*([^\r\n]+)", headers, re.I)
            file_info = {
                "filename": safe_filename(filename),
                "mimeType": (mime_match.group(1).strip() if mime_match else mimetypes.guess_type(filename)[0])
                or "application/octet-stream",
                "content": value,
            }
        else:
            fields[field_name] = value.decode("utf-8", errors="ignore")
    return fields, file_info


class SecureFileShareHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "SecureFileShare/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def log_message(self, fmt, *args):
        print(f"[HTTP] {self.address_string()} - {fmt % args}")

    def json_response(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def current_user(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:].strip()
        if not token:
            return None
        state = load_state()
        return state["sessions"].get(token)

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length < 0 or length > MAX_UPLOAD_BYTES + 2 * 1024 * 1024:
            self.json_response({"error": "Request is too large."}, 413)
            return None
        return self.rfile.read(length)

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ("/healthz/startup", "/healthz/liveness", "/healthz/readiness"):
            self.json_response({"status": "ok", "port": PORT, "timestamp": utc_now().isoformat()})
            return

        if path == "/metrics":
            self.json_response({"status": "ok", "service": "secure-file-share"})
            return

        if path == "/api/auth/me":
            user = self.current_user()
            if not user:
                self.json_response({"authenticated": False}, 401)
                return
            self.json_response({"authenticated": True, "user": {"username": user["username"], "email": user["email"]}})
            return

        if path == "/api/files":
            user = self.current_user()
            if not user:
                self.json_response({"error": "Authentication required."}, 401)
                return
            state = load_state()
            files = [
                {k: value[k] for k in (
                    "id", "originalName", "mimeType", "size", "checksum",
                    "uploadedAt", "expiresAt", "hasPassword", "scanStatus", "downloadCount"
                ) if k in value}
                for value in state["files"].values()
                if value.get("uploader") == user["username"]
            ]
            self.json_response({"files": files})
            return

        if path.startswith("/api/share-info/"):
            file_id = path.rsplit("/", 1)[-1]
            state = load_state()
            meta = state["files"].get(file_id)
            if not meta:
                self.json_response({"error": "Share link expired or invalid."}, 404)
                return
            if datetime.fromisoformat(meta["expiresAt"]) <= utc_now():
                self.expire_file(state, file_id)
                self.json_response({"error": "Share link expired."}, 410)
                return
            self.json_response({
                "id": meta["id"],
                "originalName": meta["originalName"],
                "size": meta["size"],
                "mimeType": meta["mimeType"],
                "checksum": meta["checksum"],
                "uploadedAt": meta["uploadedAt"],
                "expiresAt": meta["expiresAt"],
                "hasPassword": meta["hasPassword"],
                "scanStatus": meta["scanStatus"],
            })
            return

        if path.startswith("/share/"):
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body()
        if body is None:
            return

        if path == "/api/auth/signup":
            try:
                payload = json.loads(body.decode())
            except json.JSONDecodeError:
                self.json_response({"error": "Invalid JSON."}, 400)
                return
            username = str(payload.get("username", "")).strip()
            email = str(payload.get("email", "")).strip()
            password = str(payload.get("password", ""))
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username) or len(password) < 8 or "@" not in email:
                self.json_response({"error": "Use a valid username, email, and password of at least 8 characters."}, 400)
                return
            state = load_state()
            if username in state["users"]:
                self.json_response({"error": "Username already exists."}, 409)
                return
            user = {"username": username, "email": email, "passwordHash": hash_password(password), "createdAt": utc_now().isoformat()}
            state["users"][username] = user
            token = secrets.token_urlsafe(32)
            state["sessions"][token] = {"username": username, "email": email}
            save_state(state)
            self.json_response({"success": True, "token": token, "user": {"username": username, "email": email}}, 201)
            return

        if path == "/api/auth/login":
            try:
                payload = json.loads(body.decode())
            except json.JSONDecodeError:
                self.json_response({"error": "Invalid JSON."}, 400)
                return
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            state = load_state()
            user = state["users"].get(username)
            if not user or not verify_password(password, user.get("passwordHash", "")):
                self.json_response({"error": "Invalid username or password."}, 401)
                return
            token = secrets.token_urlsafe(32)
            state["sessions"][token] = {"username": username, "email": user["email"]}
            save_state(state)
            self.json_response({"success": True, "token": token, "user": {"username": username, "email": user["email"]}})
            return

        if path == "/api/upload":
            user = self.current_user()
            if not user:
                self.json_response({"error": "Authentication required to upload files."}, 401)
                return
            fields, file_info = parse_multipart_data(self.headers.get("Content-Type", ""), body)
            if not file_info or not file_info["content"]:
                self.json_response({"error": "No valid file attached."}, 400)
                return
            if len(file_info["content"]) > MAX_UPLOAD_BYTES:
                self.json_response({"error": f"Maximum file size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."}, 413)
                return

            password = fields.get("password", "")
            if len(password) < 8:
                self.json_response({"error": "A share password of at least 8 characters is required."}, 400)
                return
            try:
                expiry_hours = min(max(int(fields.get("expiryHours", "24")), 1), 168)
            except ValueError:
                expiry_hours = 24

            raw = file_info["content"]
            nonce, encrypted = encrypt_bytes(raw)
            file_id = str(uuid.uuid4())
            with open(os.path.join(STORAGE_DIR, f"{file_id}.enc"), "wb") as handle:
                handle.write(encrypted)

            scan_status = "not_scanned"  # Connect a real malware scanner before production use.
            meta = {
                "id": file_id,
                "originalName": file_info["filename"],
                "mimeType": file_info["mimeType"],
                "size": len(raw),
                "checksum": hashlib.sha256(raw).hexdigest(),
                "uploader": user["username"],
                "uploadedAt": utc_now().isoformat(),
                "expiresAt": (utc_now() + timedelta(hours=expiry_hours)).isoformat(),
                "hasPassword": True,
                "passwordHash": hash_password(password),
                "nonce": base64.urlsafe_b64encode(nonce).decode(),
                "scanStatus": scan_status,
                "downloadCount": 0,
            }
            state = load_state()
            state["files"][file_id] = meta
            save_state(state)
            self.json_response({
                "success": True,
                "message": "File encrypted with AES-256-GCM.",
                "file": {k: v for k, v in meta.items() if k not in ("passwordHash", "nonce", "uploader")},
                "shareUrl": f"/share/{file_id}",
            }, 201)
            return

        if path.startswith("/api/download/"):
            file_id = path.rsplit("/", 1)[-1]
            state = load_state()
            meta = state["files"].get(file_id)
            if not meta:
                self.json_response({"error": "File not found or expired."}, 404)
                return
            if datetime.fromisoformat(meta["expiresAt"]) <= utc_now():
                self.expire_file(state, file_id)
                self.json_response({"error": "Share link expired."}, 410)
                return
            try:
                payload = json.loads(body.decode()) if body else {}
            except json.JSONDecodeError:
                payload = {}
            if not verify_password(str(payload.get("password", "")), meta.get("passwordHash", "")):
                self.json_response({"error": "Incorrect share password."}, 401)
                return
            file_path = os.path.join(STORAGE_DIR, f"{file_id}.enc")
            if not os.path.exists(file_path):
                self.json_response({"error": "Encrypted payload is missing."}, 404)
                return
            try:
                with open(file_path, "rb") as handle:
                    encrypted = handle.read()
                raw = decrypt_bytes(meta["nonce"], encrypted)
            except Exception:
                self.json_response({"error": "Unable to decrypt file."}, 500)
                return

            self.send_response(200)
            self.send_header("Content-Type", meta["mimeType"])
            self.send_header("Content-Disposition", f'attachment; filename="{safe_filename(meta["originalName"])}"')
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

            try:
                os.remove(file_path)
            except OSError:
                pass
            state["files"].pop(file_id, None)
            save_state(state)
            return

        self.json_response({"error": "Not found."}, 404)

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/files/"):
            self.json_response({"error": "Not found."}, 404)
            return
        user = self.current_user()
        if not user:
            self.json_response({"error": "Authentication required."}, 401)
            return
        file_id = path.rsplit("/", 1)[-1]
        state = load_state()
        meta = state["files"].get(file_id)
        if not meta or meta.get("uploader") != user["username"]:
            self.json_response({"error": "File not found."}, 404)
            return
        try:
            os.remove(os.path.join(STORAGE_DIR, f"{file_id}.enc"))
        except OSError:
            pass
        state["files"].pop(file_id, None)
        save_state(state)
        self.json_response({"success": True})

    def expire_file(self, state, file_id):
        try:
            os.remove(os.path.join(STORAGE_DIR, f"{file_id}.enc"))
        except OSError:
            pass
        state["files"].pop(file_id, None)
        save_state(state)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    print(f"Secure File Share listening on 0.0.0.0:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), SecureFileShareHandler).serve_forever()
