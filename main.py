import os
import hmac
import hashlib
import uuid
import psycopg2
from fastapi import FastAPI, Request, HTTPException, Header, status
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Paddle License Server Pro")

# --- ---
PADDLE_WEBHOOK_SECRET = os.getenv("PADDLE_WEBHOOK_SECRET", "default_secret_for_testing_only")
DATABASE_URL = os.getenv("DATABASE_URL")

# SQL: %s Postgres, ? SQLite
DB_PLACEHOLDER = "%s" if DATABASE_URL else "?"

def get_db_connection():
    """ (PostgreSQL SQLite )"""
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    else:
        import sqlite3
        return sqlite3.connect("licenses_local.db")

def init_db():
    """ """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            customer_id TEXT,
            customer_email TEXT,
            transaction_id TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()


#
init_db()

class LicenseVerifyRequest(BaseModel):
    license_key: str

def verify_paddle_signature(request_body: bytes, signature_header: str) -> bool:
    """ Paddle v2"""
    if not signature_header or ":" not in signature_header:
        return False
    try:
        parts = dict(item.split("=") for item in signature_header.split(";"))
        timestamp = parts.get("t")
        paddle_hash = parts.get("v1")

        if not timestamp or not paddle_hash:
            return False

        signed_payload = f"{timestamp}:{request_body.decode('utf-8')}"
        computed_hash = hmac.new(
            PADDLE_WEBHOOK_SECRET.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(computed_hash, paddle_hash)
    except Exception:
        return False

@app.get("/")
def read_root():
    return {"status": "online", "message": "Paddle License Server is running like a pro."}

@app.post("/paddle-webhook")
async def handle_paddle_webhook(request: Request, paddle_signature: Optional[str] = Header(None)):
    body_bytes = await request.body()

    if PADDLE_WEBHOOK_SECRET != "default_secret_for_testing_only":
        if not paddle_signature or not verify_paddle_signature(body_bytes, paddle_signature):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Paddle signature. Access denied."
            )

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = payload.get("event_type")

    if event_type == "transaction.completed":
        data = payload.get("data", {})
        transaction_id = data.get("id")
        customer_id = data.get("customer_id")

        customer_email = "unknown"
        if "customer" in data and data["customer"]:
            customer_email = data["customer"].get("email", "unknown")

        license_key = f"KEY-{uuid.uuid4().hex.upper()}"

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            # DB_PLACEHOLDER
            query = f"INSERT INTO licenses (license_key, customer_id, customer_email, transaction_id) VALUES ({DB_PLACEHOLDER}, {DB_PLACEHOLDER}, {DB_PLACEHOLDER}, {DB_PLACEHOLDER})"
            cursor.execute(query, (license_key, customer_id, customer_email, transaction_id))
            conn.commit()
            cursor.close()
            conn.close()
            print(f"[SUCCESS] Generated license {license_key} for {customer_email}")
        except Exception as e:
            return {"status": "ignored", "reason": "Database conflict or license already exists", "error": str(e)}

        return {
            "status": "success",
            "event": event_type,
            "license_key": license_key,
            "customer_email": customer_email
        }

    return {"status": "ignored", "reason": f"Event type '{event_type}' is not handled"}

@app.post("/verify-license")
async def verify_license(payload: LicenseVerifyRequest):
    user_key = payload.license_key.strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    # DB_PLACEHOLDER
    query = f"SELECT customer_email, status, created_at FROM licenses WHERE license_key = {DB_PLACEHOLDER}"
    cursor.execute(query, (user_key,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if row:
        email, status_val, created_at = row
        if status_val == "active":
            return {
                "valid": True,
                "status": "active",
                "customer_email": email,
                "activated_at": str(created_at)
            }
        else:
            return {
                "valid": False,
                "status": status_val,
                "error": f"This license key is {status_val}"
            }

    return {
        "valid": False,
        "status": "not_found",
        "error": "The provided license key does not exist"
    }
