from functools import wraps

from flask import Blueprint, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import or_

from app.extensions import db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.responses import error_response, success_response

admin_user_bp = Blueprint(
    "superadmin_identity_admin",
    __name__,
    url_prefix="/api/internal/superadmin",
)


def superadmin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapped(*args, **kwargs):
        try:
            actor_id = int(get_jwt_identity())
        except (TypeError, ValueError):
            return error_response("Invalid token identity.", "UNAUTHORIZED", 401)
        actor = UserRepository.get_by_id(actor_id)
        if not actor or not actor.is_active:
            return error_response("Account is unavailable.", "UNAUTHORIZED", 401)
        if actor.role != User.ROLE_SUPERADMIN:
            return error_response("Superadmin access required.", "FORBIDDEN", 403)
        return fn(actor, *args, **kwargs)
    return wrapped


@admin_user_bp.get("/users")
@superadmin_required
def list_users(_actor):
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 20, type=int), 1), 100)
    role = request.args.get("role")
    status = request.args.get("status")
    search = (request.args.get("search") or "").strip()

    query = User.query
    if role:
        query = query.filter(User.role == role)
    if status == "active":
        query = query.filter(User.is_active.is_(True))
    elif status == "inactive":
        query = query.filter(User.is_active.is_(False))
    if search:
        pattern = f"%{search}%"
        query = query.filter(or_(
            User.name.ilike(pattern),
            User.email.ilike(pattern),
            User.phone.ilike(pattern),
        ))

    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return success_response({
        "items": [user.to_dict() for user in pagination.items],
        "pagination": {
            "page": pagination.page,
            "per_page": pagination.per_page,
            "total": pagination.total,
            "pages": pagination.pages,
        },
    }, "Users retrieved.")


@admin_user_bp.get("/users/<int:user_id>")
@superadmin_required
def get_user(_actor, user_id):
    user = UserRepository.get_by_id(user_id)
    if not user:
        return error_response("User not found.", "USER_NOT_FOUND", 404)
    return success_response(user.to_dict(), "User retrieved.")


@admin_user_bp.patch("/users/<int:user_id>")
@superadmin_required
def update_user(actor, user_id):
    user = UserRepository.get_by_id(user_id)
    if not user:
        return error_response("User not found.", "USER_NOT_FOUND", 404)
    if user.role == User.ROLE_SUPERADMIN:
        return error_response("Superadmin accounts cannot be edited here.", "FORBIDDEN", 403)

    payload = request.get_json(silent=True) or {}
    allowed = {"name", "email", "phone", "role"}
    unknown = set(payload) - allowed
    if unknown:
        return error_response("Unsupported fields.", "VALIDATION_ERROR", 422, {"fields": sorted(unknown)})
    if "name" in payload:
        name = str(payload["name"]).strip()
        if not name:
            return error_response("Name cannot be empty.", "VALIDATION_ERROR", 422)
        user.name = name
    if "email" in payload:
        email = str(payload["email"]).strip().lower()
        duplicate = UserRepository.get_by_email(email)
        if duplicate and duplicate.id != user.id:
            return error_response("Email is already in use.", "EMAIL_CONFLICT", 409)
        user.email = email
    if "phone" in payload:
        phone = str(payload["phone"]).strip() if payload["phone"] else None
        duplicate = UserRepository.get_by_phone_excluding_user(phone, user.id) if phone else None
        if duplicate:
            return error_response("Phone is already in use.", "PHONE_CONFLICT", 409)
        user.phone = phone
    if "role" in payload:
        role = str(payload["role"]).strip().lower()
        if role not in {User.ROLE_CLIENT, User.ROLE_ADMIN, User.ROLE_TENANT}:
            return error_response("Invalid role.", "VALIDATION_ERROR", 422)
        user.role = role
    try:
        UserRepository.update(user)
    except Exception:
        db.session.rollback()
        raise
    return success_response(user.to_dict(), "User updated.")


@admin_user_bp.patch("/users/<int:user_id>/status")
@superadmin_required
def update_user_status(actor, user_id):
    user = UserRepository.get_by_id(user_id)
    if not user:
        return error_response("User not found.", "USER_NOT_FOUND", 404)
    if user.id == actor.id and request.get_json(silent=True, force=False, cache=True) is not None:
        payload = request.get_json(silent=True) or {}
        if payload.get("is_active") is False:
            return error_response("You cannot deactivate your own account.", "FORBIDDEN", 403)
    if user.role == User.ROLE_SUPERADMIN:
        return error_response("Superadmin accounts cannot be modified here.", "FORBIDDEN", 403)

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload.get("is_active"), bool):
        return error_response("is_active must be a boolean.", "VALIDATION_ERROR", 422)
    user.is_active = payload["is_active"]
    try:
        UserRepository.update(user)
    except Exception:
        db.session.rollback()
        raise
    return success_response(user.to_dict(), "User status updated.")

@admin_user_bp.patch("/users/<int:user_id>/block")
@superadmin_required
def block_user(actor, user_id):
    return _set_user_active(actor, user_id, False)


@admin_user_bp.patch("/users/<int:user_id>/unblock")
@superadmin_required
def unblock_user(actor, user_id):
    return _set_user_active(actor, user_id, True)


def _set_user_active(actor, user_id, is_active):
    user = UserRepository.get_by_id(user_id)
    if not user:
        return error_response("User not found.", "USER_NOT_FOUND", 404)
    if user.role == User.ROLE_SUPERADMIN:
        return error_response("Superadmin accounts cannot be modified here.", "FORBIDDEN", 403)
    user.is_active = is_active
    try:
        UserRepository.update(user)
    except Exception:
        db.session.rollback()
        raise
    return success_response(user.to_dict(), "User blocked." if not is_active else "User unblocked.")
