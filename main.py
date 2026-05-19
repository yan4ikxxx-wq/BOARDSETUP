import os
import hmac
import hashlib
import uuid
import sqlite3
from fastapi import FastAPI, Request, HTTPException, Header, status
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Paddle License Server Pro")

# --- НАСТРОЙКИ БЕЗОПАСНОСТИ ---
# Секретный ключ вебхука берется из панели Paddle: Developer -> Webhooks -> Secret key
# На Render его нужно добавить во вкладку "Environment Variables" с именем PADDLE_WEBHOOK_SECRET
PADDLE_WEBHOOK_SECRET = os.getenv("PADDLE_WEBHOOK_SECRET", "default_secret_for_testing_only")

# Путь к базе данных (SQLite встроен в Python, настраивать сторонние сервисы не нужно)
DB_FILE = "licenses.db"

def init_db():
    """Инициализация базы данных при старте сервера"""
    conn = sqlite3.connect(DB_FILE)
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
    conn.close()


# Запуск базы данных при старте
init_db()

# --- МОДЕЛИ ДАННЫХ ДЛЯ ЗАПРОСОВ ---
class LicenseVerifyRequest(BaseModel):
    license_key: str

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def verify_paddle_signature(request_body: bytes, signature_header: str) -> bool:
    """
    Профессиональная проверка подписи от Paddle v2.
    Защищает ваш сервер от поддельных запросов злоумышленников.
    """
    if not signature_header or ":" not in signature_header:
        return False

    try:
        # Заголовок Paddle-Signature имеет вид: t=1672531199;h=sha256;v1=уникальный_хэш
        parts = dict(item.split("=") for item in signature_header.split(";"))
        timestamp = parts.get("t")
        paddle_hash = parts.get("v1")

        if not timestamp or not paddle_hash:
            return False

        # Формируем строку для проверки, как требует документация Paddle v2
        signed_payload = f"{timestamp}:{request_body.decode('utf-8')}"

        # Вычисляем хэш на основе нашего секретного ключа
        computed_hash = hmac.new(
            PADDLE_WEBHOOK_SECRET.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        # Сравниваем в безопасном режиме (защита от атак по времени)
        return hmac.compare_digest(computed_hash, paddle_hash)
    except Exception:
        return False

# --- ЭНДПОИНТЫ (МАРШРУТЫ СЕРВЕРА) ---

@app.get("/")
def read_root():
    return {"status": "online", "message": "Paddle License Server is running like a pro."}


@app.post("/paddle-webhook")
async def handle_paddle_webhook(request: Request, paddle_signature: Optional[str] = Header(None)):
    """
    Обработчик вебхуков от Paddle. Принимает оплату и создает лицензию в БД.
    """
    # 1. Получаем сырое тело запроса для проверки подписи
    body_bytes = await request.body()

    # 2. Проверка подписи (активируется автоматически, если ключ изменен с тестового)
    if PADDLE_WEBHOOK_SECRET != "default_secret_for_testing_only":
        if not paddle_signature or not verify_paddle_signature(body_bytes, paddle_signature):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Paddle signature. Access denied."
            )

    # 3. Читаем данные запроса
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = payload.get("event_type")

    # Реагируем только на успешную оплату транзакции
    if event_type == "transaction.completed":
        data = payload.get("data", {})

        transaction_id = data.get("id")
        customer_id = data.get("customer_id")

        # Получаем email клиента из данных Paddle v2
        customer_email = "unknown"
        if "customer" in data and data["customer"]:
            customer_email = data["customer"].get("email", "unknown")

        # Генерируем красивый и надежный уникальный ключ (Пример: KEY-A1B2C3D4...)
        license_key = f"KEY-{uuid.uuid4().hex.upper()}"

        # Сохраняем данные в базу данных SQLite
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO licenses (license_key, customer_id, customer_email, transaction_id) VALUES (?, ?, ?, ?)",
                (license_key, customer_id, customer_email, transaction_id)
            )
            conn.commit()
            conn.close()
            print(f"[SUCCESS] Generated license {license_key} for {customer_email}")
        except sqlite3.IntegrityError:
            # Защита от дублирования транзакций (если Paddle пришлет уведомление повторно)
            return {"status": "ignored", "reason": "License already exists for this transaction"}

        return {
            "status": "success",
            "event": event_type,
            "license_key": license_key,
            "customer_email": customer_email
        }

    return {"status": "ignored", "reason": f"Event type '{event_type}' is not handled"}


@app.post("/verify-license")
async def verify_license(payload: LicenseVerifyRequest):
    """
    Эндпоинт, который вызывает ВАША ПРОГРАММА при старте для проверки ключа.
    """
    user_key = payload.license_key.strip()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT customer_email, status, created_at FROM licenses WHERE license_key = ?",
        (user_key,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        email, status_val, created_at = row
        if status_val == "active":
            return {
                "valid": True,
                "status": "active",
                "customer_email": email,
                "activated_at": created_at
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
