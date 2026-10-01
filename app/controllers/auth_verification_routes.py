from flask import Blueprint, request

from app.controllers.auth_account_routes import auth_bp
from app.controllers.auth_common import _load_data
from app.extensions import limiter
from app.responses import error_response, success_response
from app.schemas.auth_verification_schema import (
    forgot_password_schema,
    reset_password_schema,
    resend_email_otp_schema,
    resend_verification_schema,
    verify_email_otp_schema,
    verify_email_schema,
)
from app.services.auth_verification_service import VerificationAuthService


@auth_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("5/minute")
def forgot_password():
    data, error = _load_data(forgot_password_schema)
    if error:
        return error
    result, message = VerificationAuthService.request_password_reset(
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
    success, message = VerificationAuthService.reset_password(
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
    result, message = VerificationAuthService.verify_email(
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
    result, message = VerificationAuthService.resend_verification(
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
    result, message = VerificationAuthService.verify_email_otp(
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
    result, message = VerificationAuthService.resend_email_otp(
        data["email"], request.remote_addr, request.headers.get("User-Agent")
    )
    if message:
        return error_response(message, "RESEND_OTP_FAILED", 400)
    return success_response(result, result["message"])
