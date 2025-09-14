from pydantic import BaseModel, EmailStr
from typing import Optional, List

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenData(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    email: str

class TokenResponse(BaseModel):
    success: bool = True
    message: str = "Login successful"
    data: TokenData
    errors: Optional[list] = None

# Pydantic models
class EmailSchema(BaseModel):
    email: List[EmailStr]
    subject: str
    body: str

class SimpleEmailSchema(BaseModel):
    to: EmailStr
    subject: str
    body: str

# Password reset schemas
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class PasswordResetResponse(BaseModel):
    success: bool = True
    message: str
    data: Optional[dict] = None
    errors: Optional[list] = None