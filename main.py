import os
import io
import csv
import random
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, EmailStr, field_validator
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

from database import db

load_dotenv()

app = FastAPI(title="WealthSense API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BROKER_PASSWORD = os.getenv("BROKER_PASSWORD", "broker123")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# ---------------------- Models ----------------------
PAN_REGEX = r"^[A-Z]{5}[0-9]{4}[A-Z]$"
PHONE_REGEX = r"^[0-9]{10}$"

class SignUpRequest(BaseModel):
    name: str
    pan: str
    address: str
    phone: str
    email: EmailStr

    @field_validator('pan')
    @classmethod
    def validate_pan(cls, v: str) -> str:
        import re
        if not re.match(PAN_REGEX, v.upper()):
            raise ValueError('Invalid PAN format. Expected 5 letters + 4 digits + 1 letter')
        return v.upper()

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v: str) -> str:
        import re
        if not re.match(PHONE_REGEX, v):
            raise ValueError('Invalid phone number. Use 10 digits')
        return v

class BrokerLoginRequest(BaseModel):
    password: str

class GenerateIdRequest(BaseModel):
    user_id: str

class SetPasswordRequest(BaseModel):
    unique_id: str
    password: str

class LoginRequest(BaseModel):
    unique_id: str
    password: str

class AddHoldingRequest(BaseModel):
    unique_id: str
    ticker: str
    quantity: int
    buy_price: float

# ---------------------- Helpers ----------------------

def users_col():
    return db["users"]

def holdings_col():
    return db["holdings"]

async def get_user_by_unique_id(unique_id: str):
    u = users_col().find_one({"unique_id": unique_id})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u

# ---------------------- Seed sample data ----------------------

def seed_data():
    if users_col().count_documents({}) == 0:
        user = {
            "unique_id": "WSN-1000",
            "name": "Asha Gupta",
            "pan": "ABCDE1234F",
            "address": "Mumbai, MH",
            "phone": "9999999999",
            "email": "asha@example.com",
            "password_hash": generate_password_hash("demo1234"),
            "status": "active",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        uid = users_col().insert_one(user).inserted_id
        holdings_col().insert_many([
            {"user_id": str(uid), "ticker": "TCS", "quantity": 10, "buy_price": 3500.0, "created_at": datetime.utcnow()},
            {"user_id": str(uid), "ticker": "RELIANCE", "quantity": 5, "buy_price": 2400.0, "created_at": datetime.utcnow()},
        ])

seed_data()

# ---------------------- Routes ----------------------

@app.get("/")
async def root():
    return {"message": "WealthSense backend is running"}

@app.post("/api/signup")
async def signup(payload: SignUpRequest):
    # Check duplicates
    if users_col().find_one({"pan": payload.pan}):
        raise HTTPException(status_code=400, detail="PAN already registered")
    if users_col().find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    doc = {
        "unique_id": None,
        "name": payload.name,
        "pan": payload.pan,
        "address": payload.address,
        "phone": payload.phone,
        "email": payload.email,
        "password_hash": None,
        "status": "pending",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = users_col().insert_one(doc)
    return {"ok": True, "user_id": str(result.inserted_id)}

@app.post("/api/broker/login")
async def broker_login(payload: BrokerLoginRequest):
    if payload.password != BROKER_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid broker password")
    return {"ok": True}

@app.get("/api/broker/pending")
async def broker_pending():
    items = list(users_col().find({"status": "pending"}, {"password_hash": 0}))
    # Convert ObjectId
    for it in items:
        it["id"] = str(it.pop("_id"))
    return {"items": items}

@app.post("/api/broker/generate_id")
async def broker_generate_id(payload: GenerateIdRequest):
    from bson import ObjectId
    try:
        _id = ObjectId(payload.user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user id")

    u = users_col().find_one({"_id": _id})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    # Find max sequence
    existing = users_col().find({"unique_id": {"$regex": "^WSN-\\d+$"}}, {"unique_id": 1})
    max_seq = 1000
    for e in existing:
        try:
            seq = int(str(e.get("unique_id", "WSN-0")).split("-")[-1])
            if seq > max_seq:
                max_seq = seq
        except Exception:
            continue
    new_id = f"WSN-{max_seq + 1}"

    users_col().update_one({"_id": _id}, {"$set": {"unique_id": new_id, "status": "active", "updated_at": datetime.utcnow()}})
    return {"ok": True, "unique_id": new_id}

@app.post("/api/auth/check")
async def auth_check(unique_id: str):
    u = await get_user_by_unique_id(unique_id)
    return {"has_password": bool(u.get("password_hash"))}

@app.post("/api/auth/set_password")
async def set_password(payload: SetPasswordRequest):
    u = await get_user_by_unique_id(payload.unique_id)
    if u.get("password_hash"):
        raise HTTPException(status_code=400, detail="Password already set")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    users_col().update_one({"_id": u["_id"]}, {"$set": {"password_hash": generate_password_hash(payload.password), "updated_at": datetime.utcnow()}})
    return {"ok": True}

@app.post("/api/auth/login")
async def login(payload: LoginRequest):
    u = await get_user_by_unique_id(payload.unique_id)
    if not u.get("password_hash"):
        raise HTTPException(status_code=400, detail="Password not set. Set it first.")
    if not check_password_hash(u["password_hash"], payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Simple sessionless auth – frontend holds unique_id
    return {"ok": True}

@app.get("/api/me")
async def me(unique_id: str):
    u = await get_user_by_unique_id(unique_id)
    u["id"] = str(u.pop("_id"))
    u.pop("password_hash", None)
    return u

@app.get("/api/holdings")
async def get_holdings(unique_id: str):
    u = await get_user_by_unique_id(unique_id)
    uid = str(u["_id"])
    items = list(holdings_col().find({"user_id": uid}))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return {"items": items}

@app.post("/api/holdings")
async def add_holding(payload: AddHoldingRequest):
    u = await get_user_by_unique_id(payload.unique_id)
    uid = str(u["_id"])
    if payload.quantity <= 0 or payload.buy_price < 0:
        raise HTTPException(status_code=400, detail="Invalid quantity or price")
    doc = {
        "user_id": uid,
        "ticker": payload.ticker.upper(),
        "quantity": int(payload.quantity),
        "buy_price": float(payload.buy_price),
        "created_at": datetime.utcnow(),
    }
    holdings_col().insert_one(doc)
    return {"ok": True}

@app.get("/api/portfolio-tip")
async def portfolio_tip(unique_id: str):
    u = await get_user_by_unique_id(unique_id)
    uid = str(u["_id"])
    items = list(holdings_col().find({"user_id": uid}))
    total_value = sum(h["quantity"] * h["buy_price"] for h in items) or 0
    by_ticker = {}
    for h in items:
        by_ticker[h["ticker"]] = by_ticker.get(h["ticker"], 0) + h["quantity"] * h["buy_price"]
    suggestion = None
    if total_value > 0:
        for t, v in by_ticker.items():
            if v / total_value > 0.6:
                suggestion = "Consider diversifying your portfolio."
                break
    return {"suggestion": suggestion or "Looking balanced. Keep reviewing your allocation periodically."}

STATIC_TIPS = [
    "Automate your investments with SIPs to build discipline.",
    "Review expense ratios on funds — lower fees boost long-term returns.",
    "Rebalance annually to maintain your target asset allocation.",
    "Avoid timing the market; focus on time in the market.",
]

@app.get("/api/quick-tip")
async def quick_tip():
    if OPENAI_API_KEY:
        try:
            import requests
            headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
            data = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are a concise finance coach."},
                    {"role": "user", "content": "Give me one practical retail investing tip in 25 words or less."}
                ],
                "max_tokens": 60
            }
            resp = requests.post("https://api.openai.com/v1/chat/completions", json=data, headers=headers, timeout=10)
            if resp.ok:
                tip = resp.json()["choices"][0]["message"]["content"].strip()
                return {"tip": tip}
        except Exception:
            pass
    return {"tip": random.choice(STATIC_TIPS)}

@app.get("/api/export-csv")
async def export_csv(unique_id: str):
    u = await get_user_by_unique_id(unique_id)
    uid = str(u["_id"])
    items = list(holdings_col().find({"user_id": uid}))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Ticker", "Quantity", "Buy Price"])
    for h in items:
        writer.writerow([h["ticker"], h["quantity"], h["buy_price"]])
    output.seek(0)
    filename = f"holdings_{u.get('unique_id','user')}.csv"
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })

@app.get("/test")
async def test_database():
    try:
        collections = db.list_collection_names()
        return {"backend": "ok", "database": "ok", "collections": collections}
    except Exception as e:
        return {"backend": "ok", "database": f"error: {e}"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
