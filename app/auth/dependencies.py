from datetime import datetime
from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.schemas.user import UserResponse
from app.models.user import User
from app.database import get_db
from sqlalchemy.orm import Session


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def get_current_user(
        token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)

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

    try:
        if isinstance(token_data, dict):
            if "username" in token_data:
                return UserResponse(**token_data)
            elif "sub" in token_data:
                user_id = token_data["sub"]
            else:
                raise credentials_exception
        elif isinstance(token_data, UUID):
            user_id = token_data
        else:
            raise credentials_exception

        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise credentials_exception

        return UserResponse.model_validate(user)

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
