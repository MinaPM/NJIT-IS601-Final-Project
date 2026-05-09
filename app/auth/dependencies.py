from datetime import datetime
from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.user import UserResponse
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Dependency to get the current user from the JWT token without a database lookup.
    This function supports two types of payloads:
      - A full payload as a dict containing user info.
      - A minimal payload, either as a dict with only a 'sub' key or directly as a UUID.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token_data = User.verify_token(token)
    if token_data is None:
        raise credentials_exception

    # Use sub as the user ID
    if isinstance(token_data, dict):
        sub = token_data.get("sub")
    elif isinstance(token_data, UUID):
        sub = token_data
    else:
        raise credentials_exception

    if sub is None:
        raise credentials_exception

    try:
        user = db.get(User, sub)
        if user is None:
            raise credentials_exception

        return UserResponse(**user.__dict__)
    except Exception:
        raise credentials_exception


def get_current_active_user(
    current_user: UserResponse = Depends(get_current_user)
) -> UserResponse:
    """
    Dependency to ensure that the current user is active.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user
