"""Path-level customer ID verification middleware."""

from __future__ import annotations

from fastapi import Depends, HTTPException

from summer_puppy.api.auth.dependencies import get_current_customer


async def verify_customer_path(
    customer_id: str,
    current_customer: str = Depends(get_current_customer),
) -> None:
    """Ensure the path customer_id matches the authenticated customer."""
    if customer_id != current_customer:
        raise HTTPException(status_code=403, detail="Customer ID mismatch")
