# app/api/v1/routers/auth.py
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm.session import Session
from supabase import create_client, Client, PostgrestAPIResponse

from app.core.config import get_settings, Settings
from app.schemas.user_schemas import CompleteInvite # <-- Add this import
from app.api.v1.dependencies import get_auth_rls_session, get_current_user, \
    get_current_user_pre_terms  # We need the user's session
from app.api.v1.security import AuthenticatedUser
from app.db.models import User
from datetime import datetime, timezone


router = APIRouter()

class UserSignup(BaseModel):
    email: EmailStr
    password: str


class ForgotPassword(BaseModel):
    email: EmailStr


def get_supabase_client(settings: Settings = Depends(get_settings)) -> Client:
    """Dependency to get a supabase client using the anon key."""
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)


@router.post("/signup", status_code=status.HTTP_201_CREATED)
def user_signup(
        payload: UserSignup,
        background_tasks: BackgroundTasks,
        supabase: Client = Depends(get_supabase_client)
):
    """
    Handles new user registration.
    Creates a user in Supabase Auth but does not create a tenant or profile yet.
    Supabase will automatically send a confirmation email.
    """
    try:
        # Supabase sign_up handles sending the confirmation email.
        response: PostgrestAPIResponse = supabase.auth.sign_up({
            "email": payload.email,
            "password": payload.password,
        })

        # We need to handle the case where the user might already exist but is unconfirmed.
        # Supabase might return a user object in this case without raising an error.
        if response.user and response.user.aud != 'authenticated':
            # This indicates the user exists but is unconfirmed.
            # You might want to resend the confirmation email here if needed.
            # For now, we'll treat it as a successful signup prompt.
            return {"message": "Signup successful. Please check your email to confirm your account."}

        if not response.user:
            # This can happen if auto-confirmation is on, which is not our case.
            # Or if there's an unexpected issue.
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Could not sign up user.")

    except Exception as e:
        # This will catch specific API errors, e.g., "User already registered"
        error_message = str(e)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=error_message)

    return {"message": "Signup successful. Please check your email to confirm your account."}


@router.post("/forgot-password")
def forgot_password(
        payload: ForgotPassword,
        supabase: Client = Depends(get_supabase_client)
):
    """
    Triggers the password reset flow for a user.
    """
    try:
        supabase.auth.reset_password_email(payload.email)
    except Exception as e:
        # Don't reveal if an email exists or not for security.
        # Log the actual error for debugging.
        print(f"Forgot password error: {e}")

    # Always return a generic success message.
    return {"message": "If an account with this email exists, a password reset link has been sent."}


@router.post("/complete-invite", status_code=status.HTTP_200_OK)
def complete_invited_user_setup(
        payload: CompleteInvite,
        # This endpoint is for an already-authenticated user (via Supabase's invite link)
        db: Session = Depends(get_auth_rls_session),
        # Use the 'pre_terms' version of the dependency that does NOT
        # perform the terms acceptance check.
        current_user: AuthenticatedUser = Depends(get_current_user_pre_terms)
):
    """
    Final step for an invited user. They set their password and accept the terms.
    The user is authenticated via the one-time token from the Supabase invite link.
    """
    if not payload.terms_accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must accept the Terms and Conditions to complete your account setup."
        )

    # Get the user's profile from our public users table
    db_user = db.query(User).filter(User.id == current_user.id).first()

    if not db_user:
        # This should theoretically never happen if the JWT is valid
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User profile not found.")

    if db_user.terms_accepted_at is not None:
        # This is not their first time, they should use the password reset flow.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Account has already been set up.")

    # Use the Supabase Admin API to update the user's password
    try:
        settings = get_settings()
        supabase_admin: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
        supabase_admin.auth.admin.update_user_by_id(
            str(current_user.id),
            {"password": payload.password}
        )
    except Exception as e:
        print(f"Error updating user password in Supabase: {e}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Could not update user password.")

    # Now, update our local user record with the terms acceptance
    db_user.terms_accepted_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": "Account setup complete. You can now log in."}


@router.post("/token")
def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
        supabase: Client = Depends(get_supabase_client)
):
    """
    Standard OAuth2 password flow. Takes email and password and returns a JWT.
    This is the primary endpoint for logging in.
    """
    try:
        # Supabase's sign_in_with_password handles the authentication
        response = supabase.auth.sign_in_with_password({
            "email": form_data.username,  # OAuth2 spec uses 'username' for the ID field
            "password": form_data.password
        })

        if not response.session or not response.session.access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Login failed. Unexpected response from auth provider."
            )

        return {
            "access_token": response.session.access_token,
            "token_type": "bearer"
        }
    except Exception as e:
        # Catch specific API errors from Supabase, e.g., "Invalid login credentials"
        error_message = str(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_message or "Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )