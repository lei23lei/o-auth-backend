from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.schemas.auth import (
    LoginRequest, TokenResponse, TokenData, 
    ForgotPasswordRequest, ResetPasswordRequest, PasswordResetResponse
)
from app.schemas.user import User, UserResponse
from app.schemas.error import ErrorResponse, ErrorDetail
from app.models.user import User as UserModel
from app.database import get_db
from app.utils.jwt import verify_password, create_access_token, verify_token, get_password_hash
from datetime import timedelta, datetime
from dotenv import load_dotenv
import os
import secrets
import uuid
from fastapi_mail import FastMail
from pydantic import EmailStr
load_dotenv()

# Email configuration
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "lei23lei61@gmail.com")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
MAIL_FROM = os.getenv("MAIL_FROM", "lei23lei61@gmail.com")

router = APIRouter(tags=["auth"])

# Security scheme
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    """Get current authenticated user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials"
    )
    
    try:
        payload = verify_token(credentials.credentials)
        if payload is None:
            raise credentials_exception
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
            
    except Exception:
        raise credentials_exception
    
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if user is None:
        raise credentials_exception
    
    return user

@router.post("/login", response_model=TokenResponse)
async def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    try:
        # Find user by email
        user = db.query(UserModel).filter(UserModel.email == login_data.email).first()
        
        if not user or not verify_password(login_data.password, user.password):
            error_response = ErrorResponse(
                message="Invalid credentials",
                errors=[ErrorDetail(field="email", message="Invalid email or password", code="INVALID_CREDENTIALS")]
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=error_response.dict()
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=30)
        access_token = create_access_token(
            data={"sub": str(user.id), "email": user.email},
            expires_delta=access_token_expires
        )
        
        # Return token response
        token_data = TokenData(
            access_token=access_token,
            expires_in=1800,  # 30 minutes in seconds
            user_id=str(user.id),
            email=user.email
        )
        
        success_response = TokenResponse(
            message="Login successful",
            data=token_data
        )
        return success_response
        
    except Exception as e:
        error_response = ErrorResponse(
            message="Login failed",
            errors=[ErrorDetail(message=str(e), code="LOGIN_ERROR")]
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.dict()
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: UserModel = Depends(get_current_user)):
    """Get current authenticated user information"""
    try:
        # Convert SQLAlchemy model to Pydantic model
        user_data = User(
            id=current_user.id,
            email=current_user.email,
            password=current_user.password,
            image=current_user.image,
            name=current_user.name,
            created_at=current_user.created_at,
            updated_at=current_user.updated_at
        )
        
        success_response = UserResponse(
            message="User information retrieved successfully",
            data=user_data
        )
        return success_response
        
    except Exception as e:
        error_response = ErrorResponse(
            message="Failed to retrieve user information",
            errors=[ErrorDetail(message=str(e), code="USER_INFO_ERROR")]
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.dict()
        )

@router.post("/forgot-password", response_model=PasswordResetResponse)
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Send password reset email to user if email is registered
    """
    try:
        # Check if user exists with the provided email
        user = db.query(UserModel).filter(UserModel.email == request.email).first()
        print(user)
        if not user:
            # For security, return success even if email doesn't exist
            # This prevents email enumeration attacks
            return PasswordResetResponse(
                success=True,
                message="Password reset email sent if account exists."
            )
        
        # Generate a secure reset token
        reset_token = secrets.token_urlsafe(32)
        
        # Set token expiration (15 minutes from now)
        token_expires = datetime.utcnow() + timedelta(minutes=15)
        
        # Save reset token to database
        user.reset_password_token = reset_token
        user.reset_password_token_expires = token_expires
        db.commit()
        
        # Create reset link (you'll need to replace with your frontend URL)
        reset_link = f"{os.getenv('FRONTEND_URL')}/reset-password?token={reset_token}"
        
        # Email content
        subject = "Password Reset Request"
        body = f"""
        <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello {user.name or 'User'},</p>
            <p>You have requested to reset your password. Click the link below to reset your password:</p>
            <p><a href="{reset_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
            <p>This link will expire in 15 minutes.</p>
            <p>If you didn't request this password reset, please ignore this email.</p>
            <br>
            <p>Best regards,<br>Your App Team</p>
        </body>
        </html>
        """
        
        # Send email using ConnectionConfig (the correct approach)
        from fastapi_mail import ConnectionConfig, MessageSchema
        
        conf = ConnectionConfig(
            MAIL_USERNAME=MAIL_USERNAME,
            MAIL_PASSWORD=MAIL_PASSWORD,
            MAIL_FROM=MAIL_FROM,
            MAIL_PORT=587,
            MAIL_SERVER="smtp.gmail.com",
            MAIL_STARTTLS=True,
            MAIL_SSL_TLS=False,
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=False
        )
        
        fm = FastMail(conf)
        
        message = MessageSchema(
            subject=subject,
            recipients=[request.email],
            body=body,
            subtype="html"
        )
        
        await fm.send_message(message)
        
        return PasswordResetResponse(
            success=True,
            message="Password reset email sent if account exists."
        )
        
    except Exception as e:
        # Log the error for debugging but don't expose it to the user
        print(f"Error sending password reset email: {str(e)}")
        
        error_response = ErrorResponse(
            message="Failed to send password reset email",
            errors=[ErrorDetail(message="An error occurred while processing your request", code="EMAIL_SEND_ERROR")]
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.dict()
        )

@router.post("/reset-password", response_model=PasswordResetResponse)
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Reset user password using the reset token from email
    """
    try:
        # Find user by reset token
        user = db.query(UserModel).filter(
            UserModel.reset_password_token == request.token
        ).first()
        
        if not user:
            error_response = ErrorResponse(
                message="Invalid or expired reset token",
                errors=[ErrorDetail(field="token", message="The reset token is invalid or has expired", code="INVALID_TOKEN")]
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=error_response.dict()
            )
        
        # Check if token has expired
        if user.reset_password_token_expires and user.reset_password_token_expires < datetime.utcnow():
            # Clear expired token
            user.reset_password_token = None
            user.reset_password_token_expires = None
            db.commit()
            
            error_response = ErrorResponse(
                message="Reset token has expired",
                errors=[ErrorDetail(field="token", message="The reset token has expired. Please request a new password reset", code="TOKEN_EXPIRED")]
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=error_response.dict()
            )
        
        # Validate new password (basic validation)
        if len(request.new_password) < 8:
            error_response = ErrorResponse(
                message="Password too short",
                errors=[ErrorDetail(field="new_password", message="Password must be at least 8 characters long", code="PASSWORD_TOO_SHORT")]
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=error_response.dict()
            )
        
        # Update user password
        user.password = get_password_hash(request.new_password)
        user.reset_password_token = None  # Clear the token
        user.reset_password_token_expires = None  # Clear expiration
        user.updated_at = datetime.utcnow()
        db.commit()
        
        return PasswordResetResponse(
            success=True,
            message="Password has been reset successfully",
            data={"email": user.email}
        )
        
    except Exception as e:
        # Log the error for debugging but don't expose it to the user
        print(f"Error resetting password: {str(e)}")
        
        error_response = ErrorResponse(
            message="Failed to reset password",
            errors=[ErrorDetail(message="An error occurred while resetting your password", code="RESET_ERROR")]
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.dict()
        )