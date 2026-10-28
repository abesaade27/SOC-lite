"""Authentication dependency verifying X-API-Key with constant-time comparison."""

import hmac
from fastapi import Header, HTTPException, status
from .config import settings


async def verify_api_key(x_api_key: str = Header(None, alias="X-API-Key")) -> str:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required header 'X-API-Key'",
        )
    if not hmac.compare_digest(x_api_key, settings.API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key provided",
        )
    return x_api_key
