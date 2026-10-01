import logging
from datetime import datetime, timezone

from flask import Blueprint, request
from flask_jwt_extended import (
	decode_token,
	get_jwt,
	get_jwt_identity,
	jwt_required,
)
from marshmallow import ValidationError

from app.extensions import limiter
from app.models.token_blocklist import TokenBlocklist
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.responses import error_response, success_response, validation_error_response
from app.schemas.auth_schema import (
	ChangePasswordSchema,
	ForgotPasswordSchema,
	LoginSchema,
	RegisterClientSchema,
	RegisterTenantSchema,
	ResendEmailOtpSchema,
	ResendVerificationSchema,
	ResetPasswordSchema,
	UpdateProfileSchema,
	VerifyEmailOtpSchema,
	VerifyEmailSchema,
)
from app.security import generate_token_pair
from app.services.auth_service import AuthService


logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")
users_bp = Blueprint("users", __name__, url_prefix="/api/users")

register_tenant_schema = RegisterTenantSchema()
register_client_schema = RegisterClientSchema()
login_schema = LoginSchema()
forgot_password_schema = ForgotPasswordSchema()
reset_password_schema = ResetPasswordSchema()
verify_email_schema = VerifyEmailSchema()
resend_verification_schema = ResendVerificationSchema()
verify_email_otp_schema = VerifyEmailOtpSchema()
resend_email_otp_schema = ResendEmailOtpSchema()
update_profile_schema = UpdateProfileSchema()
change_password_schema = ChangePasswordSchema()


def _load_data(schema):
	try:
		return schema.load(request.get_json(silent=True) or {}), None
	except ValidationError as error:
		return None, validation_error_response(error.messages)


def _active_user():
	identity = get_jwt_identity()
	user = UserRepository.get_by_id(int(identity)) if identity else None
	if not user or not user.is_active:
		return None, error_response(
			"User not found or account deactivated.", "UNAUTHORIZED", 401
		)
	if user.role in {User.ROLE_CLIENT, User.ROLE_ADMIN} and user.client_id is not None:
		if user.client_status is None:
			return None, error_response(
				"Client status is not synchronized with Auth Service.",
				"CLIENT_STATUS_UNAVAILABLE",
				503,
			)
		if user.client_status in User.INVALID_CLIENT_STATUSES:
			return None, error_response(
				f"Your client organization account is {user.client_status}.",
				"CLIENT_INACTIVE",
				403,
			)
	return user, None


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
	result, message = AuthService.register_tenant(data)
	if message:
		return error_response(message, "REGISTRATION_FAILED", 409)
	return success_response(result, "Tenant registered successfully.", 201)


@auth_bp.route("/register-client", methods=["POST"])
@limiter.limit("10/minute")
def register_client():
	data, error = _load_data(register_client_schema)
	if error:
		return error
	result, message = AuthService.register_client(data)
	if message:
		return error_response(message, "CLIENT_SERVICE_REQUIRED", 503)
	return success_response(result, "Client organization registered successfully.", 201)


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10/minute")
def login():
	data, error = _load_data(login_schema)
	if error:
		return error
	result, message, status = AuthService.authenticate_user(data)
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
	user = UserRepository.get_by_id(int(identity)) if identity else None
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


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
	user, error = _active_user()
	if error:
		return error
	return success_response(user.to_dict(), "Current user profile retrieved.")


@auth_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("5/minute")
def forgot_password():
	data, error = _load_data(forgot_password_schema)
	if error:
		return error
	result, message = AuthService.request_password_reset(
		data["email"], request.remote_addr, request.headers.get("User-Agent")
	)
	if message:
		status = 404 if message.startswith("No account found") else 400
		code = "USER_NOT_FOUND" if status == 404 else "FORGOT_PASSWORD_FAILED"
		return error_response(message, code, status)
	return success_response(data={}, message=result["message"])


@auth_bp.route("/reset-password", methods=["POST"])
@limiter.limit("5/minute")
def reset_password():
	data, error = _load_data(reset_password_schema)
	if error:
		return error
	success, message = AuthService.reset_password(
		data["token"],
		data["password"],
		request.remote_addr,
		request.headers.get("User-Agent"),
	)
	if not success:
		return error_response(message or "Password reset failed.", "RESET_FAILED", 400)
	return success_response(message="Password reset successfully. You may now log in with your new password.")


@auth_bp.route("/verify-email", methods=["POST"])
@limiter.limit("15/minute")
def verify_email():
	data, error = _load_data(verify_email_schema)
	if error:
		return error
	result, message = AuthService.verify_email(
		data["token"], request.remote_addr, request.headers.get("User-Agent")
	)
	if message:
		return error_response(message, "VERIFICATION_FAILED", 400)
	return success_response(result, result["message"])


@auth_bp.route("/resend-verification", methods=["POST"])
@limiter.limit("5/minute")
def resend_verification():
	data, error = _load_data(resend_verification_schema)
	if error:
		return error
	result, message = AuthService.resend_verification(
		data["email"], request.remote_addr, request.headers.get("User-Agent")
	)
	if message:
		return error_response(message, "RESEND_FAILED", 400)
	return success_response(result, result["message"])


@auth_bp.route("/verify-email-otp", methods=["POST"])
@limiter.limit("15/minute")
def verify_email_otp():
	data, error = _load_data(verify_email_otp_schema)
	if error:
		return error
	result, message = AuthService.verify_email_otp(
		data["email"], data["otp"], request.remote_addr, request.headers.get("User-Agent")
	)
	if message:
		return error_response(message, "OTP_VERIFICATION_FAILED", 400)
	return success_response(result, result["message"])


@auth_bp.route("/resend-email-otp", methods=["POST"])
@limiter.limit("5/minute")
def resend_email_otp():
	data, error = _load_data(resend_email_otp_schema)
	if error:
		return error
	result, message = AuthService.resend_email_otp(
		data["email"], request.remote_addr, request.headers.get("User-Agent")
	)
	if message:
		return error_response(message, "RESEND_OTP_FAILED", 400)
	return success_response(result, result["message"])


@users_bp.route("/me", methods=["GET"])
@jwt_required()
def get_my_profile():
	user, error = _active_user()
	if error:
		return error
	return success_response(user.to_dict(), "Profile retrieved.")


@users_bp.route("/me", methods=["PUT"])
@jwt_required()
def update_my_profile():
	user, error = _active_user()
	if error:
		return error
	data, error = _load_data(update_profile_schema)
	if error:
		return error
	updated, message = AuthService.update_profile(user, data)
	if message:
		status = 409 if "already in use" in message.lower() else 400
		return error_response(message, "PROFILE_UPDATE_FAILED", status)
	return success_response(updated, "Profile updated successfully.")


@users_bp.route("/me/password", methods=["PATCH"])
@jwt_required()
def change_my_password():
	user, error = _active_user()
	if error:
		return error
	data, error = _load_data(change_password_schema)
	if error:
		return error
	success, message = AuthService.change_password(
		user, data["current_password"], data["new_password"]
	)
	if not success:
		return error_response(message, "PASSWORD_CHANGE_FAILED", 400)
	return success_response(message="Password changed successfully.")
