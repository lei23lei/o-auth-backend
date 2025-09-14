from pydantic import BaseModel
from typing import List, Optional, Any

class ErrorDetail(BaseModel):
    field: Optional[str] = None
    message: str
    code: Optional[str] = None

class ErrorResponse(BaseModel):
    success: bool = False
    message: str
    errors: Optional[List[ErrorDetail]] = None
    data: Optional[Any] = None

class ValidationErrorDetail(BaseModel):
    field: str
    message: str
    value: Optional[Any] = None

class ValidationErrorResponse(BaseModel):
    success: bool = False
    message: str = "Validation failed"
    errors: List[ValidationErrorDetail]

# Universal response schema for consistency
class BaseResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    errors: Optional[List[ErrorDetail]] = None
