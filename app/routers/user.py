from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.schemas.user import User, UserCreate, UserResponse
from app.schemas.error import ErrorResponse, ErrorDetail, BaseResponse
from app.models.user import User as UserModel
from app.database import get_db
from app.utils.jwt import get_password_hash

router = APIRouter(tags=["user"])

@router.get("/", response_model=BaseResponse)
async def get_users():
    return BaseResponse(
        success=True,
        message="Hello User",
        data=None
    )

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        # Check if user already exists
        existing_user = db.query(UserModel).filter(UserModel.email == user.email).first()
        if existing_user:
            # Handle cross-provider email conflicts
            if existing_user.provider != "email":
                # User exists with OAuth provider (e.g., GitHub)
                error_response = ErrorResponse(
                    message="Account already exists with OAuth provider",
                    errors=[ErrorDetail(
                        field="email", 
                        message=f"An account with this email already exists using {existing_user.provider} login. Please use {existing_user.provider} to sign in.", 
                        code="ACCOUNT_EXISTS_OAUTH"
                    )]
                )
                return JSONResponse(
                    status_code=status.HTTP_409_CONFLICT,
                    content=error_response.dict()
                )
            else:
                # User already has email account
                error_response = ErrorResponse(
                    message="Email already registered",
                    errors=[ErrorDetail(field="email", message="This email is already in use", code="EMAIL_EXISTS")]
                )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content=error_response.dict()
                )
        
        # Create new user with hashed password
        db_user = UserModel(
            email=user.email, 
            password=get_password_hash(user.password),
            image=None,
            name=None,
            provider="email",  # Explicitly set provider for email registration
            provider_id=None,  # No provider ID for email users
            username=None      # No username for email users
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        # Convert SQLAlchemy model to Pydantic model
        user_data = User(
            id=db_user.id,
            email=db_user.email,
            password=db_user.password,
            image=db_user.image,
            name=db_user.name,
            provider=db_user.provider,
            provider_id=db_user.provider_id,
            username=db_user.username,
            created_at=db_user.created_at,
            updated_at=db_user.updated_at
        )
        
        # Return consistent success response
        success_response = UserResponse(
            message="User created successfully",
            data=user_data
        )
        return success_response
        
    except IntegrityError as e:
        db.rollback()
        if "unique constraint" in str(e).lower():
            error_response = ErrorResponse(
                message="Email already registered",
                errors=[ErrorDetail(field="email", message="This email is already in use", code="EMAIL_EXISTS")]
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=error_response.dict()
            )
        error_response = ErrorResponse(
            message="Database integrity error",
            errors=[ErrorDetail(message="A database constraint was violated", code="DB_INTEGRITY_ERROR")]
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.dict()
        )
    except Exception as e:
        db.rollback()
        error_response = ErrorResponse(
            message="An error occurred while creating user",
            errors=[ErrorDetail(message=str(e), code="INTERNAL_ERROR")]
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.dict()
        )
        
        
