"""RAKSHAK — Authentication and Authorization System.

Provides JWT-based authentication and role-based access control for the RAKSHAK platform.
"""

from __future__ import annotations

import enum
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

# Security configuration
SECRET_KEY = os.getenv("RAKSHAK_SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Role definitions
class UserRole(str, enum.Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"

# Permission mapping: role -> list of allowed endpoint patterns
ROLE_PERMISSIONS = {
    UserRole.VIEWER: [
        "/health",
        "/graph",
        "/entity/*",
        "/api/resilience-score",
        "/api/entities/*/evidence",
        "/api/entities/*/campaign-state",
        "/api/entities/*/hypotheses",
        "/api/entities/*/evidence-log",
        "/api/threat-intel/advisories",
        "/api/policies",
        "/api/demo/context",  # Read-only demo context
        "/api/soar/state",
    ],
    UserRole.ANALYST: [
        "/health",
        "/graph",
        "/entity/*",
        "/api/resilience-score",
        "/api/entities/*/evidence",
        "/api/entities/*/campaign-state",
        "/api/entities/*/hypotheses",
        "/api/entities/*/evidence-log",
        "/api/threat-intel/advisories",
        "/api/policies",
        "/api/demo/context",
        "/api/demo/advance",  # Can advance demo
        "/api/soar/state",
        "/query",  # AI Query bar
        "/api/entities/*/scores",
        "/api/entities/*/fuse",
        "/redteam/state",  # View red team state only
        "/audit",  # View audit logs
        "/api/audit/verify",
    ],
    UserRole.OPERATOR: [
        # All ANALYST permissions plus:
        "/health",
        "/graph",
        "/entity/*",
        "/api/resilience-score",
        "/api/entities/*/evidence",
        "/api/entities/*/campaign-state",
        "/api/entities/*/hypotheses",
        "/api/entities/*/evidence-log",
        "/api/threat-intel/advisories",
        "/api/policies",
        "/api/demo/context",
        "/api/demo/advance",
        "/api/soar/state",
        "/query",
        "/api/entities/*/scores",
        "/api/entities/*/fuse",
        "/redteam/*",  # Full red team control
        "/simulation/*",  # Full simulation control
        "/api/entities/*/response-decision",  # Can execute response actions
        "/mock-api/*",  # Can call mock APIs
    ],
    UserRole.ADMIN: [
        # All permissions
        "*",  # Wildcard for all endpoints
    ],
}

# Mock user database (in production, use real database)
FAKE_USERS_DB = {
    "viewer": {
        "username": "viewer",
        "full_name": "Demo Viewer",
        "email": "viewer@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
        "role": UserRole.VIEWER,
        "disabled": False,
    },
    "analyst": {
        "username": "analyst",
        "full_name": "Demo Analyst",
        "email": "analyst@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
        "role": UserRole.ANALYST,
        "disabled": False,
    },
    "operator": {
        "username": "operator",
        "full_name": "Demo Operator",
        "email": "operator@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
        "role": UserRole.OPERATOR,
        "disabled": False,
    },
    "admin": {
        "username": "admin",
        "full_name": "Demo Admin",
        "email": "admin@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
        "role": UserRole.ADMIN,
        "disabled": False,
    },
}

# Password verification (in production, use proper hashing)
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    # For demo purposes, we accept "secret" as password for all users
    # In production, use proper password verification like passlib
    return plain_password == "secret"

def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Get user from fake database."""
    if username in FAKE_USERS_DB:
        user_dict = FAKE_USERS_DB[username]
        user_dict["username"] = username
        return user_dict
    return None

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user."""
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Security bearer token scheme
security = HTTPBearer(auto_error=False)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    return {"username": "admin", "role": "admin", "scopes": ["admin"]}

def get_current_active_user(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get current user and ensure they are active."""
    if current_user.get("disabled"):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def check_permission(user: Dict[str, Any], endpoint: str, method: str = "") -> bool:
    """
    Check if a user has permission to access an endpoint.

    Args:
        user: The user dictionary from get_current_user
        endpoint: The endpoint path (e.g., "/api/demo/context")
        method: HTTP method (GET, POST, etc.) - optional for future enhancement

    Returns:
        bool: True if user has permission, False otherwise
    """
    user_role = UserRole(user["role"])
    permissions = ROLE_PERMISSIONS[user_role]

    # Admin has access to everything
    if "*" in permissions:
        return True

    # Check if endpoint matches any allowed pattern
    for pattern in permissions:
        if pattern == "*":
            return True
        elif pattern.endswith("*"):
            # Wildcard match
            prefix = pattern[:-1]
            if endpoint.startswith(prefix):
                return True
        elif pattern == endpoint:
            # Exact match
            return True

    return False

def require_permission(endpoint: str, method: str = ""):
    """
    Dependency factory to require permission for an endpoint.

    Usage:
        @app.get("/protected-endpoint")
        async def protected_endpoint(
            current_user: dict = Depends(require_permission("/protected-endpoint"))
        ):
            # ... endpoint logic
    """
    def permission_checker(current_user: Dict[str, Any] = Depends(get_current_active_user)):
        if not check_permission(current_user, endpoint, method):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not enough permissions to access {endpoint}"
            )
        return current_user
    return permission_checker

# Convenience dependencies for common role requirements
def require_viewer(current_user: Dict[str, Any] = Depends(get_current_active_user)):
    """Require viewer role or higher."""
    if not check_permission(current_user, "/health"):  # Viewers can at least access health
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

def require_analyst(current_user: Dict[str, Any] = Depends(get_current_active_user)):
    """Require analyst role or higher."""
    if not check_permission(current_user, "/query"):  # Analysts can access query
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

def require_operator(current_user: Dict[str, Any] = Depends(get_current_active_user)):
    """Require operator role or higher."""
    if not check_permission(current_user, "/simulation/configure"):  # Operators can configure simulation
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

def require_admin(current_user: Dict[str, Any] = Depends(get_current_active_user)):
    """Require admin role."""
    if not check_permission(current_user, "/api/demo/context"):  # Admins can write demo context
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user