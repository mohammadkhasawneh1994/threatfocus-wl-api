from typing import Any, Dict, Optional
from layers.app.python.fastapi import HTTPException, status


class ServiceException(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class EntityNotFoundException(ServiceException):
    def __init__(self, entity_name: str, entity_id: str):
        super().__init__(
            code="RESOURCE_NOT_FOUND",
            message=f"{entity_name} with ID '{entity_id}' was not found.",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DuplicateResourceException(ServiceException):
    def __init__(self, message: str):
        super().__init__(
            code="DUPLICATE_RESOURCE",
            message=message,
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidIndicatorException(ServiceException):
    def __init__(self, message: str, code: str = "INVALID_INDICATOR"):
        super().__init__(
            code=code,
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class UnauthorizedAccessException(ServiceException):
    def __init__(self, message: str = "Tenant authorization failed"):
        super().__init__(
            code="UNAUTHORIZED_TENANT_ACCESS",
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
        )