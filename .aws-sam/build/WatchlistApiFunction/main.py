from layers.app.python.fastapi import FastAPI, Request
from layers.app.python.fastapi.responses import JSONResponse
from mangum import Mangum

from app.api.v1.endpoints import router as v1_router
from app.core.exceptions import ServiceException
from app.core.logging import logger, setup_logging

setup_logging()

app = FastAPI(
    title="ThreatFocus Watchlist Service",
    description=(
        "Tenant-scoped watchlist and indicator management API. "
        "Use the Bearer token issued by the API Gateway JWT authorizer."
    ),
    version="1.0.0",
    openapi_tags=[
        {
            "name": "Health",
            "description": "Service availability checks.",
        },
        {
            "name": "Watchlists",
            "description": "Create and manage tenant watchlists.",
        },
        {
            "name": "Indicators",
            "description": "Add and remove indicators within a watchlist.",
        },
        {
            "name": "Snapshots",
            "description": "Read the effective watchlist configuration for a tenant.",
        },
    ],
    docs_url="/docs",
    redoc_url="/redoc",
)

# Exception Handler
@app.exception_handler(ServiceException)
async def service_exception_handler(request: Request, exc: ServiceException):
    logger.warning(f"Domain Service Exception: {exc.code} - {exc.message}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.get(
    "/health",
    tags=["Health"],
    summary="Check service health",
    description="Returns the current availability status of the watchlist service.",
    response_description="The service is healthy.",
)
async def health_check():
    return {"status": "HEALTHY", "service": "watchlist-service"}


app.include_router(v1_router)

# Mangum AWS Lambda Handler Initialization
handler = Mangum(app, api_gateway_base_path=None)