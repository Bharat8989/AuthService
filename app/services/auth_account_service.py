import logging
import os
import secrets
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.email_verification import EmailVerificationHistory
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.security import (
	generate_token_pair,
	normalize_email,
	validate_email_format,
	validate_password_strength,
)
from app.services.auth_common_service import send_email
from app.services.graph_email_service import GraphEmailService

logger = logging.getLogger(__name__)


class AccountAuthService:
	@staticmethod
	def _register_user(data: dict, *, role: str, name: str, client_status: str | None = None):
		email = normalize_email(data.get("email"))
		valid, message = validate_email_format(email)
		if not valid:
			return None, message
		if UserRepository.get_by_email(email):
			return None, "A user with this email already exists."

		phone = data.get("phone")
		if phone and UserRepository.get_by_phone(phone):
			return None, "A user with this phone number already exists."

		user = User(
			name=name,
			email=email,
			phone=phone.strip() if phone else None,
			role=role,
			client_id=None,
			client_status=client_status,
			is_active=True,
			email_verified=False,
		)
		user.set_password(data["password"])
		otp = f"{secrets.randbelow(1_000_000):06d}"
		user.set_otp(otp)
		try:
			db.session.add(user)
			db.session.flush()
			db.session.add(
				EmailVerificationHistory(
					user_id=user.id,
					status=EmailVerificationHistory.STATUS_SENT,
					ip_address=data.get("ip_address"),
					user_agent=data.get("user_agent"),
				)
			)
			db.session.commit()
		except IntegrityError:
			db.session.rollback()
			return None, "A user with this email or phone number already exists."
		except Exception:
			db.session.rollback()
			logger.exception("User registration failed.")
			return None, "Registration failed. Please try again."

		send_email(GraphEmailService.send_otp_email, user, otp)
		result = user.to_dict()
		result["needs_email_verification"] = True
		return result, None

	@staticmethod
	def register_tenant(data: dict) -> tuple[dict | None, str | None]:
		name = (data.get("name") or "").strip()
		if not name:
			return None, "Name is required."
		return AccountAuthService._register_user(
			data, role=User.ROLE_TENANT, name=name
		)

	@staticmethod
	def register_client(data: dict) -> tuple[dict | None, str | None]:
		name = (
			data.get("owner_name") or data.get("name") or data.get("company_name") or ""
		).strip()
		if not name:
			return None, "Owner name is required."
		return AccountAuthService._register_user(
			data,
			role=User.ROLE_CLIENT,
			name=name,
			client_status=User.CLIENT_STATUS_PENDING,
		)

	@staticmethod
	def authenticate_user(data: dict) -> tuple[dict | None, str | None, int]:
		email = normalize_email(data.get("email"))
		user = UserRepository.get_by_email(email)
		if not user or not user.check_password(data.get("password", "")):
			logger.warning("Failed login attempt for email=%s", email)
			return None, "Invalid email or password.", 401
		if not user.is_active:
			return None, "Your account has been deactivated or blocked.", 403
		if user.role not in User.VALID_ROLES:
			return None, "Account has an unsupported role.", 403
		if not user.email_verified and user.role in {User.ROLE_TENANT, User.ROLE_CLIENT}:
			return {
				"needs_email_verification": True,
				"email": user.email,
			}, "Email verification required. Please verify your email with the OTP sent to your inbox.", 403

		if user.role in {User.ROLE_CLIENT, User.ROLE_ADMIN} and user.client_id is not None:
			if user.client_status is None:
				return None, "Client status is not synchronized with Auth Service.", 503
			if user.client_status in User.INVALID_CLIENT_STATUSES:
				return None, f"Your client organization account is {user.client_status}.", 403

		tokens = generate_token_pair(user)
		return {"tokens": tokens, "user": user.to_dict()}, None, 200

	@staticmethod
	def sync_superadmin_logic() -> tuple[bool, str]:
		raw_email = os.getenv("SUPERADMIN_EMAIL")
		raw_password = os.getenv("SUPERADMIN_PASSWORD")
		if not raw_email or not raw_email.strip():
			return False, "SUPERADMIN_EMAIL environment variable is not configured or empty."
		if not raw_password or not raw_password.strip():
			return False, "SUPERADMIN_PASSWORD environment variable is not configured or empty."
		email = normalize_email(raw_email)
		valid, message = validate_email_format(email)
		if not valid:
			return False, f"Invalid SUPERADMIN_EMAIL format: {message}"
		valid, message = validate_password_strength(raw_password)
		if not valid:
			return False, f"SUPERADMIN_PASSWORD does not meet security requirements: {message}"

		superadmins = User.query.filter_by(role=User.ROLE_SUPERADMIN).all()
		if len(superadmins) > 1:
			return False, "Multiple Super Admin records found; resolve manually."
		user = superadmins[0] if superadmins else UserRepository.get_by_email(email)
		if user:
			duplicate = UserRepository.get_by_email(email)
			if duplicate and duplicate.id != user.id:
				return False, f"Cannot assign Super Admin email; it is already assigned to user ID {duplicate.id}."
			user.email = email
			user.role = User.ROLE_SUPERADMIN
			user.client_id = None
			user.client_status = None
			user.is_active = True
			user.email_verified = True
			user.email_verified_at = datetime.now(timezone.utc)
			user.set_password(raw_password)
			user.token_version = (user.token_version or 1) + 1
			db.session.commit()
			return True, f"Super Admin synchronized successfully for email '{email}' (ID: {user.id})."

		user = User(
			name="Platform Super Administrator",
			email=email,
			role=User.ROLE_SUPERADMIN,
			client_id=None,
			is_active=True,
			email_verified=True,
			email_verified_at=datetime.now(timezone.utc),
		)
		user.set_password(raw_password)
		db.session.add(user)
		db.session.commit()
		return True, f"New Super Admin account created successfully (ID: {user.id})."