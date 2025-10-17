# app/crud/tenant_crud.py
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from supabase import create_client, Client
from uuid import UUID

from app.core.permissions import AppPermissions
from app.db.models import Tenant, UserRole, User
from app.schemas.plan_schemas import TenantPlanAssignment
from app.schemas.tenant_schemas import TenantCreate, TenantUpdate, TenantOnboard  # Import TenantUpdate
from app.api.v1.security import AuthenticatedUser

def create_tenant_with_admin_user(
    db: Session,
    tenant_data: TenantCreate,
    supabase_url: str,
    supabase_key: str
) -> Tenant:
    """
    Performs the complete tenant onboarding process as a single transaction.
    ... (docstring)
    """
    supabase_admin: Client = create_client(supabase_url, supabase_key)

    # --- THIS IS THE REFACTORED PART ---
    # 1. Create the user using the admin method
    try:
        # Use the admin-specific user creation method.
        # This is more appropriate for backend operations and less likely to be rate-limited.
        # We set email_confirm=True to mimic the standard sign_up flow.
        auth_response = supabase_admin.auth.admin.create_user({
            "email": tenant_data.admin_email,
            "password": tenant_data.admin_password,
            "email_confirm": True,  # Marks the email as confirmed immediately
        })
        new_auth_user = auth_response.user
        if not new_auth_user:
            raise Exception("Failed to create user in Supabase Auth via admin API.")
    except Exception as e:
        # Handle API errors from Supabase, which might be wrapped in a list
        error_message = str(e)
        if "User already exists" in error_message:
             raise ValueError("Supabase Auth error: User already exists")
        # Handle other potential errors
        raise ValueError(f"Supabase Auth error: {error_message}")
    # --- END OF REFACTOR ---

    # The rest of the function remains the same...
    # 2. Create the Tenant record in our database
    new_tenant = Tenant(
        name=tenant_data.name,
        slug=tenant_data.slug,
        created_by=new_auth_user.id

    )
    db.add(new_tenant)
    db.flush()

    # 3. Create a default 'Admin' role for this tenant
    admin_role = UserRole(
        name="Admin",
        tenant_id=new_tenant.id,
        is_admin_role=True,
        permission_set=AppPermissions.TENANT_ADMIN_PERMISSIONS.value,
        created_by=new_auth_user.id
    )
    db.add(admin_role)
    db.flush()

    # 4. Create the User profile record in our public table
    new_user_profile = User(
        id=new_auth_user.id,
        email=tenant_data.admin_email,
        tenant_id=new_tenant.id,
        role_id=admin_role.id,
        created_by=new_auth_user.id,
        updated_by=new_auth_user.id,
        terms_accepted_at=datetime.now(timezone.utc)
    )
    db.add(new_user_profile)
    db.flush()

    # 5. Link the new user as the tenant's admin_user_id
    new_tenant.admin_user_id = new_user_profile.id
    db.add(new_tenant)

    return new_tenant


def get_tenant_by_id_superadmin(db: Session, tenant_id: UUID) -> Tenant | None:
    """
    Retrieves a single tenant by ID. This function is intended for superadmin use,
    as it directly queries without RLS scope (since the superadmin bypasses it).
    """
    return db.query(Tenant).filter(Tenant.id == tenant_id).first()


def get_all_tenants_superadmin(db: Session) -> list[Tenant]:
    """
    Retrieves all tenants. This function is intended for superadmin use,
    as it directly queries without RLS scope.
    """
    tenant__all = db.query(Tenant).all()
    return tenant__all


def update_tenant_superadmin(
        db: Session,
        db_tenant: Tenant,
        tenant_update: TenantUpdate,
        updater_id: UUID
) -> Tenant:
    """
    Updates an existing tenant's details. Intended for superadmin.
    """
    update_data = tenant_update.dict(exclude_unset=True)  # Use by_alias to handle metadata_
    for key, value in update_data.items():
        setattr(db_tenant, key, value)

    db_tenant.updated_by = updater_id
    db.add(db_tenant)
    db.flush()
    return db_tenant


def delete_tenant_superadmin(
        db: Session,
        db_tenant: Tenant,
        supabase_admin: Client
):
    """
    Deletes a tenant and all associated users from Supabase Auth.
    This is a cascade delete operation.
    """
    # First, get all users belonging to this tenant to delete them from Supabase Auth
    # Note: RLS does not apply here because we're using a superadmin connection in Python logic
    users_to_delete = db.query(User).filter(User.tenant_id == db_tenant.id).all()

    for user in users_to_delete:
        try:
            supabase_admin.auth.admin.delete_user(str(user.id))
        except Exception as e:
            print(f"Warning: Could not delete user {user.id} from Supabase Auth during tenant deletion. Error: {e}")
            # Log this, but proceed with local deletion as the main goal is clean DB state

    # SQLAlchemy's cascade delete on foreign keys (ON DELETE CASCADE)
    # in the DB schema will handle deleting user_roles, users, and items after tenant deletion.
    db.delete(db_tenant)
    db.flush()


def get_tenant_by_id(db: Session, tenant_id: UUID) -> Tenant | None:
    """
    Retrieves a single tenant by ID. This function is for tenant members
    and respects RLS policies.
    """
    # This query will only return a result if the current user belongs to the tenant.
    return db.query(Tenant).filter(Tenant.id == tenant_id).first()


def update_tenant(db: Session, db_tenant: Tenant, tenant_update: TenantUpdate, updater_id: UUID) -> Tenant:
    """
    Updates an existing tenant's details. This is for a tenant admin to update their own tenant.
    """
    # Use exclude_unset=True so we only update fields that were actually provided.
    update_data = tenant_update.dict(exclude_unset=True)

    for key, value in update_data.items():
        setattr(db_tenant, key, value)

    db_tenant.updated_by = updater_id
    db.add(db_tenant)
    db.flush()
    return db_tenant


def create_tenant_for_new_user(db: Session, tenant_data: TenantOnboard, user: AuthenticatedUser) -> Tenant:
    """
    Creates a tenant, an admin role, and the user's profile during the
    self-service onboarding flow.
    """
    # 1. Create the Tenant record
    new_tenant = Tenant(
        name=tenant_data.name,
        slug=tenant_data.slug,
        created_by=user.id
    )
    db.add(new_tenant)
    db.flush()

    # 2. Create the default 'Admin' role for this new tenant
    admin_role = UserRole(
        name="Admin",
        tenant_id=new_tenant.id,
        is_admin_role=True,
        permission_set=AppPermissions.TENANT_ADMIN_PERMISSIONS.value,
        created_by=user.id
    )
    db.add(admin_role)
    db.flush()

    # 3. Create the user's profile record in our public table
    # This user already exists in Supabase Auth, so we get their email from there.
    # A more robust solution might fetch the email from Supabase Admin API.
    # For now, we assume the frontend can provide it or we can get it from the token.
    # NOTE: The AuthenticatedUser model does not currently contain the email.
    # We need to fetch it.
    from supabase import create_client
    # This is a temporary solution for getting the email. A better way would be to pass
    # it from the frontend or have it in the JWT.
    # settings = get_settings() # You would need to get settings here
    # supabase_admin = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
    # auth_user = supabase_admin.auth.admin.get_user_by_id(user.id).user
    # user_email = auth_user.email
    # For now, we'll assume the email needs to be added to our flow.
    # Let's add a step to get user details including email.

    # We will need to update our AuthenticatedUser model and get_current_user_data
    # to include the email to solve this cleanly.

    new_user_profile = User(
        id=user.id,
        email=user.email,  # <-- This needs to be added to AuthenticatedUser
        tenant_id=new_tenant.id,
        role_id=admin_role.id,
        created_by=user.id,
        updated_by=user.id,
        terms_accepted_at=datetime.now(timezone.utc)
    )
    db.add(new_user_profile)
    db.flush()

    # 4. Link the new user as the tenant's admin_user_id
    new_tenant.admin_user_id = new_user_profile.id
    db.add(new_tenant)

    return new_tenant


def assign_plan_to_tenant(db: Session, db_tenant: Tenant, plan_assign: TenantPlanAssignment, updater_id: UUID) -> Tenant:
    """Manually assigns a subscription plan to a tenant."""
    db_tenant.plan_id = plan_assign.plan_id
    db_tenant.subscription_status = plan_assign.subscription_status
    db_tenant.current_period_ends_at = plan_assign.current_period_ends_at
    db_tenant.updated_by_id = updater_id
    db.add(db_tenant)
    db.flush()
    return db_tenant