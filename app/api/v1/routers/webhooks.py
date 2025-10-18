# app/api/v1/routers/webhooks.py
from uuid import UUID
import stripe

from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from pydantic import BaseModel

from app.api.v1.dependencies import get_system_db_session
from app.services.dodo_service import dodo_service
from app.db.models import Tenant, User, Plan, WebhookEvent  # <-- Import WebhookEvent
from app.services.stripe_service import stripe_service

router = APIRouter()


# Helper Pydantic model for parsing the webhook headers
class DodoWebhookHeaders(BaseModel):
    webhook_id: str
    webhook_signature: str
    webhook_timestamp: str


@router.post("/dodo", status_code=status.HTTP_202_ACCEPTED)  # Use 202 for "Accepted for processing"
async def handle_dodo_webhook(
        request: Request,
        db: Session = Depends(get_system_db_session)  # Use a plain session for this handler
):
    """
    Handles incoming webhooks from Dodo Payments with idempotency and
    out-of-order handling.
    """
    # 1. Extract Headers and Verify Signature
    try:
        headers = DodoWebhookHeaders(
            webhook_id=request.headers.get("webhook-id"),
            webhook_signature=request.headers.get("webhook-signature"),
            webhook_timestamp=request.headers.get("webhook-timestamp"),
        )
        payload = await dodo_service.verify_webhook_signature(request)
    except Exception as e:
        print(f"ERROR: Webhook signature verification failed or headers missing: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid headers or signature.")

    # 2. Idempotency Check: Has this event already been processed?
    event_id = headers.webhook_id
    event_type = payload.get("type")
    event_to_process = db.query(WebhookEvent).filter(WebhookEvent.id == event_id).first()
    if event_to_process:
        # Event record already exists.
        if event_to_process.processed_successfully:
            # If it was already processed successfully, this is a true duplicate.
            print(f"INFO: Received and skipped already processed Stripe webhook (id: {event_id}).")
            return {"status": "duplicate", "message": "Event already processed successfully."}
        else:
            # If it exists but was not processed successfully, this is a retry of a failed event.
            # We will re-process it.
            print(f"INFO: Retrying previously failed Stripe webhook (id: {event_id}).")
    else:
        # This is a brand new event.
        event_to_process = WebhookEvent(id=event_id, event_type=event_type, payload=payload)
        db.add(event_to_process)
        # We flush here to ensure the record is in the session, but don't commit yet.
        db.flush()

    # 3. Process the Event
    try:
        # Re-fetch the event to ensure we are working with a committed record
        process_event(db, event_to_process)

        # Mark as successfully processed and commit.
        event_to_process.processed_successfully = True
        db.commit()

        return {"status": "processed"}
    except HTTPException as e:
        db.rollback()
        # If our logic intentionally raises an HTTP error (e.g., 404),
        # we still want to return 200 to Dodo so it doesn't retry.
        print(f"ERROR: Could not process webhook {event_id}. Reason: {e.detail}")
        return {"status": "error", "detail": e.detail}
    except Exception as e:
        db.rollback()
        print(f"CRITICAL: An unexpected error occurred processing webhook {event_id}. Error: {e}")
        # An unexpected error means we should let Dodo retry.
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error.")


@router.post("/stripe", status_code=status.HTTP_200_OK)
async def handle_stripe_webhook(
        request: Request,
        db: Session = Depends(get_system_db_session)
):
    """
    Handles incoming webhooks from Stripe with robust idempotency, retry-safety,
    and a single atomic transaction.
    """

    # 1. Verify Signature
    try:
        event = await stripe_service.verify_webhook_signature(request)
    except HTTPException as e:
        return {"status": "error", "detail": e.detail}

    event_id = event['id']
    event_type = event['type']

    # 2. Idempotency and Retry Logic
    event_to_process = db.query(WebhookEvent).filter(WebhookEvent.id == event_id).first()

    if event_to_process:
        # Event record already exists.
        if event_to_process.processed_successfully:
            # If it was already processed successfully, this is a true duplicate.
            print(f"INFO: Received and skipped already processed Stripe webhook (id: {event_id}).")
            return {"status": "duplicate", "message": "Event already processed successfully."}
        else:
            # If it exists but was not processed successfully, this is a retry of a failed event.
            # We will re-process it.
            print(f"INFO: Retrying previously failed Stripe webhook (id: {event_id}).")
    else:
        # This is a brand new event.
        event_to_process = WebhookEvent(id=event_id, event_type=event_type, payload=event.to_dict())
        db.add(event_to_process)
        # We flush here to ensure the record is in the session, but don't commit yet.
        db.flush()

    # 3. Process the Event
    try:
        # We pass the ORM object to the processing function.
        process_stripe_event(db, event_to_process)

        # Mark as successfully processed.
        event_to_process.processed_successfully = True

        # The single commit for the entire transaction will be handled by the
        # `get_system_db_session` dependency when the function exits.

        print(f"INFO: Successfully processed Stripe webhook (id: {event_id}).")
        return {"status": "processed"}

    except HTTPException as e:
        # Business logic failure (e.g., Tenant not found). Don't retry.
        db.rollback()
        print(f"ERROR: Could not process Stripe webhook {event_id}. Reason: {e.detail}")
        return {"status": "error", "detail": e.detail}

    except Exception as e:
        # Unexpected system failure. Roll back and let Stripe retry.
        db.rollback()
        print(f"CRITICAL: Unexpected error processing Stripe webhook {event_id}. Error: {e}")
        raise

def process_stripe_event(db: Session, event: WebhookEvent):
    """The core business logic for handling a Stripe webhook event."""
    event_type = event.event_type
    data_object = event.payload['data']['object']

    print(f"INFO: Processing Stripe webhook event: {event_type} (id: {event.id})")

    tenant = None
    # Find the tenant based on the event type
    if event_type.startswith('checkout.session.'):
        client_reference_id = data_object.get('client_reference_id')
        if not client_reference_id:
            raise HTTPException(status_code=400, detail="Missing client_reference_id in checkout session.")
        tenant = db.query(Tenant).filter(Tenant.id == UUID(client_reference_id)).first()
    elif data_object.get('customer'):
        customer_id = data_object.get('customer')
        tenant = db.query(Tenant).filter(Tenant.external_customer_id == customer_id).first()

    if not tenant:
        raise HTTPException(status_code=404, detail=f"Could not find tenant for event {event_type} with ID {event.id}.")

    # Out-of-order handling
    event_timestamp = datetime.fromtimestamp(event.payload['created'], tz=timezone.utc)
    if tenant.updated_at and event_timestamp < tenant.updated_at.replace(tzinfo=timezone.utc):
        print(f"INFO: Skipping stale Stripe event (id: {event.id}).")
        return

    # State Machine Logic
    if event_type == 'checkout.session.completed':
        if data_object.get('mode') == 'subscription':
            subscription_id = data_object.get('subscription')
            customer_id = data_object.get('customer')

            if not subscription_id or not customer_id:
                raise HTTPException(status_code=400, detail="Subscription or Customer ID missing in webhook payload.")

            # --- THIS IS THE FIX ---
            # Retrieve the full subscription object to get all details
            try:
                subscription = stripe.Subscription.retrieve(subscription_id)
            except Exception as e:
                print(f"ERROR: Could not retrieve Stripe subscription {subscription_id}. Error: {e}")
                raise HTTPException(status_code=500, detail="Could not retrieve subscription details from Stripe.")

            # Safely get the price ID from the nested structure
            try:
                price_id = subscription.get('items', {}).get('data', [{}])[0].get('price', {}).get('id')
            except (IndexError, AttributeError):
                price_id = None

            if not price_id:
                raise HTTPException(status_code=400, detail="Price ID not found in Stripe subscription object.")

            plan = db.query(Plan).filter(Plan.external_price_id == price_id).first()
            if not plan:
                print(f"WARNING: Could not find an internal plan matching Stripe price ID: {price_id}")
                # We can still proceed without the plan, but the tenant won't have entitlements.

            # Update tenant record
            tenant.plan_id = plan.id if plan else None
            tenant.subscription_status = 'active'
            tenant.external_subscription_id = subscription_id
            tenant.external_customer_id = customer_id

            # Safely get the period end timestamp
            period_end_timestamp = subscription.get('current_period_end')
            if period_end_timestamp:
                tenant.current_period_ends_at = datetime.fromtimestamp(period_end_timestamp, tz=timezone.utc)

            print(
                f"INFO: Tenant {tenant.id} subscription activated for plan '{plan.name if plan else 'Unknown'}' via Stripe.")

    elif event_type == 'invoice.payment_failed':
        tenant.subscription_status = 'past_due'
        print(f"INFO: Tenant {tenant.id} subscription set to past_due.")

    elif event_type in ['customer.subscription.deleted', 'customer.subscription.updated']:
        # For updates, check the status field.
        # For deleted, the status will be 'canceled'.
        status = data_object.get('status')
        if data_object.get('cancel_at_period_end'):
            tenant.subscription_status = 'canceled'
            print(f"INFO: Tenant {tenant.id} subscription set to be canceled at period end.")
        elif status in ['canceled', 'unpaid']:
            tenant.subscription_status = 'inactive'
            print(f"INFO: Tenant {tenant.id} subscription set to inactive.")

    else:
        print(f"INFO: Unhandled Stripe event type: {event_type}")

    # The commit is handled by the main webhook function
    return

def process_event(db: Session, event: WebhookEvent):
    """
    The core business logic for handling a webhook event.
    This is separated for clarity and testability.
    """
    event_type = event.event_type
    payload = event.payload
    data = payload.get("data", {})

    print(f"INFO: Processing webhook event: {event_type} (id: {event.id})")

    # The payload timestamp is what we use for out-of-order checks.
    event_timestamp = datetime.fromisoformat(payload.get("timestamp").replace("Z", "+00:00"))

    # Extract key identifiers from the payload
    subscription_data = data
    external_subscription_id = subscription_data.get("subscription_id")
    customer_data = subscription_data.get("customer", {})
    customer_email = customer_data.get("email")

    if not external_subscription_id or not customer_email:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Webhook missing key identifiers.")

    # Fetch our internal tenant
    user = db.query(User).filter(User.email == customer_email).first()
    if not user or not user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Tenant for email {customer_email} not found.")

    tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
    if not tenant:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Tenant record {user.tenant_id} not found.")

    # --- Out-of-Order Handling ---
    # Before changing the status, check if a newer event has already updated the period end date.
    if tenant.current_period_ends_at and event_timestamp < tenant.current_period_ends_at.replace(tzinfo=timezone.utc):
        print(
            f"INFO: Skipping stale webhook event (id: {event.id}). Event timestamp {event_timestamp} is older than last update {tenant.current_period_ends_at}.")
        return  # Acknowledge and skip processing this old event.

    # --- State Machine Logic ---
    if event_type == "subscription.active" or event_type == "subscription.renewed":
        # ... (logic to find plan, update tenant status to 'active', etc.)
        external_product_id = subscription_data.get("product_id")
        plan = db.query(Plan).filter(Plan.external_product_id == external_product_id).first()
        if not plan: raise HTTPException(status.HTTP_404_NOT_FOUND,
                                         f"Plan with external_id {external_product_id} not found.")

        tenant.plan_id = plan.id
        tenant.subscription_status = 'active'
        tenant.external_subscription_id = external_subscription_id
        # Update the period end date from the payload
        period_ends_at_str = subscription_data.get("period_ends_at")
        if period_ends_at_str:
            tenant.current_period_ends_at = datetime.fromisoformat(period_ends_at_str.replace("Z", "+00:00"))

    elif event_type == "subscription.on_hold" or event_type == "subscription.failed":
        tenant.subscription_status = 'past_due'

    elif event_type == "subscription.cancelled" or event_type == "subscription.expired":
        tenant.subscription_status = 'inactive'

    else:
        print(f"INFO: Unhandled event type: {event_type}")

    return