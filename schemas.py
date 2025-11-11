from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional
import re

PAN_REGEX = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
PHONE_REGEX = re.compile(r"^[0-9]{10}$")

class User(BaseModel):
    unique_id: Optional[str] = Field(None, description="Assigned by broker e.g., WSN-1001")
    name: str
    pan: str
    address: str
    phone: str
    email: EmailStr
    password_hash: Optional[str] = None
    status: str = Field("pending", description="pending|active")

    @field_validator('pan')
    @classmethod
    def validate_pan(cls, v: str) -> str:
        if not PAN_REGEX.match(v.upper()):
            raise ValueError('Invalid PAN format. Expected 5 letters + 4 digits + 1 letter')
        return v.upper()

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v: str) -> str:
        if not PHONE_REGEX.match(v):
            raise ValueError('Invalid phone number. Use 10 digits')
        return v

class Holding(BaseModel):
    user_id: str
    ticker: str
    quantity: int = Field(..., ge=1)
    buy_price: float = Field(..., ge=0)
