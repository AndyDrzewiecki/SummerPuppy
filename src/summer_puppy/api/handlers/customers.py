"""Customer onboarding and status endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from summer_puppy.api.auth.api_key_handler import generate_api_key
from summer_puppy.api.middleware.auth_middleware import verify_customer_path
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.tenants.models import TenantProfile
from summer_puppy.trust.models import TrustPhase, TrustProfile

router = APIRouter()


class RegisterCustomerRequest(BaseModel):
    customer_id: str
    display_name: str = ""


class RegisterCustomerResponse(BaseModel):
    customer_id: str
    tenant_id: str
    trust_phase: str
    api_key: str  # raw key, shown ONCE


class CustomerStatusResponse(BaseModel):
    customer_id: str
    tenant_id: str
    trust_phase: str
    total_recommendations: int
    total_approvals: int
    total_rejections: int


@router.post("", response_model=RegisterCustomerResponse, status_code=201)
async def register_customer(
    body: RegisterCustomerRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> RegisterCustomerResponse:
    """Register a new customer (no auth required — bootstrap)."""
    if state.tenant_store.get(body.customer_id) is not None:
        raise HTTPException(status_code=409, detail="Customer already exists")

    tenant = TenantProfile(customer_id=body.customer_id)
    state.tenant_store.save(tenant)

    trust_profile = TrustProfile(customer_id=body.customer_id)
    state.trust_store[body.customer_id] = trust_profile

    raw_key, api_key = generate_api_key(body.customer_id)
    state.tenant_store.save_api_key(api_key)

    return RegisterCustomerResponse(
        customer_id=body.customer_id,
        tenant_id=tenant.tenant_id,
        trust_phase=TrustPhase.MANUAL.value,
        api_key=raw_key,
    )


@router.get(
    "/{customer_id}",
    response_model=CustomerStatusResponse,
    dependencies=[Depends(verify_customer_path)],  # noqa: B008
)
async def get_customer_status(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> CustomerStatusResponse:
    """Return the status and metrics for a registered customer."""
    tenant = state.tenant_store.get(customer_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Customer not found")

    trust_profile = state.trust_store.get(customer_id) or TrustProfile(customer_id=customer_id)

    return CustomerStatusResponse(
        customer_id=customer_id,
        tenant_id=tenant.tenant_id,
        trust_phase=trust_profile.trust_phase.value,
        total_recommendations=trust_profile.total_recommendations,
        total_approvals=trust_profile.total_approvals,
        total_rejections=trust_profile.total_rejections,
    )
