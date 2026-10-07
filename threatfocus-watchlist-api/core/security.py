from typing import Any, Dict
from fastapi import Depends, HTTPException, Request, status, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

from core.config import settings
from core.exceptions import UnauthorizedAccessException

security_scheme = HTTPBearer()


class TenantContext:
    def __init__(self, tenant_id: str, claims: Dict[str, Any]):
        self.tenant_id = tenant_id
        self.claims = claims


async def get_tenant_context(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> TenantContext:
    token = credentials.credentials
    try:
        # Decode without strict signature verification for ALB/API Gateway HTTP API proxy setups,
        # where JWT token signature verification is offloaded to the API Gateway JWT Authorizer.
        # Ensure 'tenant_id' or 'custom:tenant_id' is decoded safely.
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
        tenant_id = unverified_claims.get("tenant_id") or unverified_claims.get("custom:tenant_id")
        
        if not tenant_id or not isinstance(tenant_id, str):
            raise UnauthorizedAccessException("Missing valid tenant_id claim in authenticated token.")
            
        return TenantContext(tenant_id=tenant_id, claims=unverified_claims)
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authorization token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_tenant_context_from_param(
    tenant_id: str = Query(
        ..., 
        alias="tenant_id", 
        description="The unique identifier for the tenant."
    ),
) -> TenantContext:
    """
    Extracts tenant_id from request query parameters and returns a TenantContext.
    Usage endpoint: GET /endpoint?tenant_id=your-tenant-id
    """
    # Clean and validate the tenant_id string
    tenant_id_clean = tenant_id.strip()
    
    if not tenant_id_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or empty 'tenant_id' query parameter.",
        )
        
    return TenantContext(tenant_id=tenant_id_clean, claims={})