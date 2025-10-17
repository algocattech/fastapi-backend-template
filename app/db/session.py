# app/db/session.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import text
from app.api.v1.security import get_token_data # You will need to import this
from fastapi import Depends

from app.core.config import get_settings

# Get database URL from settings
DATABASE_URL = get_settings().DATABASE_URL

# Create the SQLAlchemy engine.
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

# Create a configured "Session" class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get a basic, non-RLS DB session
def get_db():
    """
    FastAPI dependency that provides a SQLAlchemy database session.
    It ensures the session is always closed after the request is finished.
    Use this for public or non-RLS-aware endpoints.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db_with_user_id(token_data: dict = Depends(get_token_data)):
    """
    Provides a DB session with the 'app.current_user_id' set.
    This is used for the initial user lookup where we only have the JWT.
    """
    db = SessionLocal()
    user_id = token_data.get("user_id")
    try:
        if user_id:
            # Set the user ID for the new 'user_can_select_self_policy' RLS policy
            db.execute(text("SET app.current_user_id = :user_id"), {"user_id": user_id})
        yield db
    finally:
        # Important to reset the setting
        db.execute(text("RESET app.current_user_id"))
        db.close()