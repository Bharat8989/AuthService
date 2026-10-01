from flask import Blueprint
from flask_jwt_extended import jwt_required

from app.controllers.auth_common import _active_user, _load_data
from app.responses import error_response, success_response
from app.schemas.auth_profile_schema import change_password_schema, update_profile_schema
from app.services.auth_profile_service import ProfileAuthService

users_bp = Blueprint("users", __name__, url_prefix="/api/users")


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
    updated, message = ProfileAuthService.update_profile(user, data)
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
    success, message = ProfileAuthService.change_password(
        user, data["current_password"], data["new_password"]
    )
    if not success:
        return error_response(message, "PASSWORD_CHANGE_FAILED", 400)
    return success_response(message="Password changed successfully.")
