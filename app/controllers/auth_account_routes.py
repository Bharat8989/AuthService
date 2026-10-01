import logging
from datetime import datetime, timezone

from flask import Blueprint, request
from flask_jwt_extended import decode_token, get_jwt, get_jwt_identity, jwt_required

from app.controllers.auth_common import _load_data
from app.extensions import limiter
from app.models.token_blocklist import TokenBlocklist
from app.responses import error_response, success_response
from app.schemas.auth_account_schema import login_schema, register_client_schema, register_tenant_schema
from app.security import generate_token_pair
from app.services.auth_account_service import AccountAuthService

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/test-logging", methods=["GET"])
def test_logging():
    logger.error("TEST ERROR LOG")
    return {"message": "Test log generated"}, 200


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("10/minute")
def register_tenant():
    data, error = _load_data(register_tenant_schema)
    if error:
        return error
    data["ip_address"] = request.remote_addr
    data["user_agent"] = request.headers.get("User-Agent")
    result, message = AccountAuthService.register_tenant(data)
    if message:
        return error_response(message, "REGISTRATION_FAILED", 409)
    return success_response(result, "Tenant registered successfully.", 201)


@auth_bp.route("/register-client", methods=["POST"])
@limiter.limit("10/minute")
def register_client():
    data, error = _load_data(register_client_schema)
    if error:
        return error
    data["ip_address"] = request.remote_addr
    data["user_agent"] = request.headers.get("User-Agent")
    result, message = AccountAuthService.register_client(data)
    if message:
        return error_response(message, "CLIENT_REGISTRATION_FAILED", 409)
    return success_response(result, "Client organization registered successfully.", 201)


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10/minute")
def login():
    data, error = _load_data(login_schema)
    if error:
        return error
    result, message, status = AccountAuthService.authenticate_user(data)
    if message:
        error_code = (
            "EMAIL_NOT_VERIFIED"
            if status == 403 and isinstance(result, dict) and result.get("needs_email_verification")
            else "AUTH_FAILED"
        )
        if status == 503:
            error_code = "CLIENT_STATUS_UNAVAILABLE"
        return error_response(message, error_code, status, details=result)
    return success_response(result, "Login successful.")


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    identity = get_jwt_identity()
    user = None
    if identity:
        from app.repositories.user_repository import UserRepository
        user = UserRepository.get_by_id(int(identity))
    if not user or not user.is_active:
        return error_response("User is inactive or not found.", "UNAUTHORIZED", 401)
    claims = get_jwt()
    expiry = claims.get("exp")
    expires_at = datetime.fromtimestamp(expiry, tz=timezone.utc) if expiry else None
    TokenBlocklist.revoke_token(claims.get("jti"), "refresh", user.id, expires_at)
    tokens = generate_token_pair(user)
    return success_response(
        {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": "Bearer",
        },
        "Access token refreshed successfully.",
    )


@auth_bp.route("/logout", methods=["POST"])
@jwt_required(optional=True)
def logout():
    claims = get_jwt()
    identity = get_jwt_identity()
    if claims and identity and claims.get("jti"):
        expiry = claims.get("exp")
        expires_at = datetime.fromtimestamp(expiry, tz=timezone.utc) if expiry else None
        TokenBlocklist.revoke_token(
            claims["jti"], claims.get("type", "access"), int(identity), expires_at
        )

    raw_refresh = (request.get_json(silent=True) or {}).get("refresh_token")
    if raw_refresh:
        try:
            decoded = decode_token(raw_refresh)
            subject = decoded.get("sub")
            expiry = decoded.get("exp")
            expires_at = datetime.fromtimestamp(expiry, tz=timezone.utc) if expiry else None
            if decoded.get("jti") and subject:
                TokenBlocklist.revoke_token(
                    decoded["jti"], "refresh", int(subject), expires_at
                )
        except Exception:
            pass
    return success_response(message="Logged out successfully.")
