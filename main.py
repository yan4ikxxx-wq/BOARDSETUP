import os
import hmac
import hashlib
import uuid
import sqlite3
from fastapi import FastAPI, Request, HTTPException, Header, status
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Paddle License Server Pro")

# Считываем секретный ключ из настроек Render (Notification Setting ID)
PADDLE_WEBHOOK_SECRET = os.getenv("PADDLE_WEBHOOK_SECRET", "default_secret_for_testing_only")

# Считываем URL базы данных PostgreSQL из настроек Render
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    """
    Универсальное подключение: если есть DATABASE_URL — подключается к PostgreSQL,
    если нет — использует локальный SQLite (для тестов на компьютере).
    """
    if DATABASE_URL:
        # Если мы в облаке Render, используем PostgreSQL
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    else:
        # Если мы запускаем локально, используем SQLite
        return sqlite3.connect("licenses_local.db")

def init_db():
    """Создает таблицу лицензий, если её ещё нет"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Текст запроса (подходит и для SQLite, и для PostgreSQL)
    query = """
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            customer_id TEXT,
            customer_email TEXT,
            transaction_id TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    cursor.execute(query)
    conn.commit()
    conn.close()


# Инициализируем базу данных при старте
init_db()

class LicenseVerifyRequest(BaseModel):
    license_key: str

def verify_paddle_signature(request_body: bytes, signature_header: str) -> bool:
    """Проверка подлинности запроса от Paddle v2"""
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

    # Если секрет настроен, строго проверяем подпись Paddle
    if PADDLE_WEBHOOK_SECRET != "default_secret_for_testing_only":
        if not paddle_signature or not verify_paddle_signature(body_bytes, paddle_signature):
            print("[WARNING] Invalid Paddle signature rejected.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Paddle signature."
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

        # Генерируем уникальный лицензионный ключ
        license_key = f"KEY-{uuid.uuid4().hex.upper()}"

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Используем универсальный плейсхолдер %s для обеих БД
            query = "INSERT INTO licenses (license_key, customer_id, customer_email, transaction_id) VALUES (%s, %s, %s, %s)"

            # Маленький фикс для SQLite, так как он не понимает %s по умолчанию
            if not DATABASE_URL:
                query = query.replace("%s", "?")

            cursor.execute(query, (license_key, customer_id, customer_email, transaction_id))
            conn.commit()
            conn.close()
            print(f"[SUCCESS] Generated license {license_key} for {customer_email}")
        except Exception as e:
            print(f"[ERROR] Database error: {e}")
            return {"status": "error", "reason": str(e)}

        return {
            "status": "success",
            "license_key": license_key,
            "customer_email": customer_email
        }

    return {"status": "ignored", "reason": f"Event type '{event_type}' not handled"}

@app.post("/verify-license")
async def verify_license(payload: LicenseVerifyRequest):
    user_key = payload.license_key.strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT customer_email, status, created_at FROM licenses WHERE license_key = %s"
    if not DATABASE_URL:
        query = query.replace("%s", "?")

    cursor.execute(query, (user_key,))
    row = cursor.fetchone()
    conn.close()

    if row:
        email, status_val, created_at = row
        if status_val == "active":
            return {
                "valid": True,
                "status": "active",
                "customer_email": email
            }
        return {"valid": False, "status": status_val}

    return {"valid": False, "status": "not_found"}
