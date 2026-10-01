from flask import request
from flask_jwt_extended import get_jwt_identity
from marshmallow import ValidationError

from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.responses import error_response, validation_error_response


def _load_data(schema):
	try:
		return schema.load(request.get_json(silent=True) or {}), None
	except ValidationError as error:
		return None, validation_error_response(error.messages)


def _active_user():
	identity = get_jwt_identity()
	user = UserRepository.get_by_id(int(identity)) if identity else None
	if not user or not user.is_active:
		return None, error_response("User not found or account deactivated.", "UNAUTHORIZED", 401)
	if user.role in {User.ROLE_CLIENT, User.ROLE_ADMIN} and user.client_id is not None:
		if user.client_status is None:
			return None, error_response(
				"Client status is not synchronized with Auth Service.", "CLIENT_STATUS_UNAVAILABLE", 503
			)
		if user.client_status in User.INVALID_CLIENT_STATUSES:
			return None, error_response(
				f"Your client organization account is {user.client_status}.", "CLIENT_INACTIVE", 403
			)
	return user, None
