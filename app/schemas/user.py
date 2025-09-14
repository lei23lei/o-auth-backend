from pydantic import BaseModel, EmailStr, validator
from datetime import datetime
import uuid
import re
from typing import Optional

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Za-z]', v):
            raise ValueError('Password must contain at least one letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        return v

class User(BaseModel):
    id: uuid.UUID
    image: Optional[str] = None
    email: str
    password: str
    name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class UserResponse(BaseModel):
    success: bool = True
    message: str = "User created successfully"
    data: User
    errors: Optional[list] = None