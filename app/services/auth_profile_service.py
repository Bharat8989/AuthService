import secrets

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.email_verification import EmailVerificationHistory
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.security import normalize_email
from app.services.auth_common_service import send_email
from app.services.graph_email_service import GraphEmailService


class ProfileAuthService:
	@staticmethod
	def update_profile(user: User, data: dict) -> tuple[dict | None, str | None]:
		if data.get("name"):
			user.name = data["name"].strip()
		if data.get("email"):
			email = normalize_email(data["email"])
			duplicate = UserRepository.get_by_email(email)
			if duplicate and duplicate.id != user.id:
				return None, "This email address is already in use by another account."
			if email != user.email:
				user.email = email
				user.email_verified = False
				user.email_verified_at = None
				otp = f"{secrets.randbelow(1_000_000):06d}"
				user.set_otp(otp)
				db.session.add(EmailVerificationHistory(user_id=user.id, status=EmailVerificationHistory.STATUS_SENT))
			else:
				otp = None
		else:
			otp = None

		if "phone" in data:
			phone = data["phone"].strip() if data["phone"] else None
			duplicate = UserRepository.get_by_phone_excluding_user(phone, user.id) if phone else None
			if duplicate:
				return None, "This phone number is already in use by another account."
			user.phone = phone
		try:
			db.session.commit()
		except IntegrityError:
			db.session.rollback()
			return None, "Email or phone number is already in use."
		if otp:
			send_email(GraphEmailService.send_otp_email, user, otp)
		return user.to_dict(), None

	@staticmethod
	def change_password(user: User, current_password: str, new_password: str) -> tuple[bool, str | None]:
		if not user.check_password(current_password):
			return False, "Current password does not match."
		if current_password == new_password:
			return False, "New password cannot be the same as your current password."
		user.set_password(new_password)
		user.token_version = (user.token_version or 1) + 1
		db.session.commit()
		send_email(GraphEmailService.send_password_changed_email, user)
		return True, None