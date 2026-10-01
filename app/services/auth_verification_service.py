import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models.email_verification import EmailVerificationHistory
from app.models.password_reset import PasswordResetHistory
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.security import normalize_email, validate_email_format
from app.services.auth_common_service import (
	aware,
	latest_reset,
	latest_verification,
	send_email,
	update_latest_reset,
	update_latest_verification,
)
from app.services.graph_email_service import GraphEmailService


class VerificationAuthService:
	@staticmethod
	def verify_email(token: str, ip_address: str | None = None, user_agent: str | None = None):
		if not token or not token.strip():
			return None, "Verification token is required."
		user = UserRepository.get_by_verification_token(token.strip())
		if not user:
			return None, "Invalid or expired verification token."

		now = datetime.now(timezone.utc)
		if user.verification_token_expires_at and aware(user.verification_token_expires_at) < now:
			update_latest_verification(user.id, EmailVerificationHistory.STATUS_EXPIRED)
			user.verification_token = None
			user.verification_token_expires_at = None
			db.session.commit()
			return None, "Verification token has expired. Please request a new verification link."

		user.email_verified = True
		user.email_verified_at = now
		user.verification_token = None
		user.verification_token_expires_at = None
		history = latest_verification(user.id)
		if history:
			history.status = EmailVerificationHistory.STATUS_VERIFIED
			history.verified_at = now
		else:
			db.session.add(EmailVerificationHistory(
				user_id=user.id, requested_at=now, verified_at=now,
				status=EmailVerificationHistory.STATUS_VERIFIED,
				ip_address=ip_address, user_agent=user_agent,
			))
		db.session.commit()
		send_email(GraphEmailService.send_welcome_email, user)
		return {"message": "Email verified successfully. You can now log in."}, None

	@staticmethod
	def resend_verification(email: str, ip_address: str | None = None, user_agent: str | None = None):
		valid, message = validate_email_format(email)
		if not valid:
			return None, message
		response = {"message": "If an unverified account exists for this email, a new verification link has been sent."}
		user = UserRepository.get_by_email(normalize_email(email))
		if not user or not user.is_active or user.email_verified:
			return response, None

		now = datetime.now(timezone.utc)
		token = secrets.token_urlsafe(32)
		user.verification_token = token
		user.verification_token_expires_at = now + timedelta(minutes=60)
		db.session.add(EmailVerificationHistory(
			user_id=user.id, requested_at=now, status=EmailVerificationHistory.STATUS_SENT,
			ip_address=ip_address, user_agent=user_agent,
		))
		db.session.commit()
		send_email(GraphEmailService.send_verification_email, user, token, expiry_minutes=60)
		return response, None

	@staticmethod
	def verify_email_otp(email: str, otp: str, ip_address: str | None = None, user_agent: str | None = None):
		if not email or not otp:
			return None, "Email address and 6-digit OTP are required."
		user = UserRepository.get_by_email(normalize_email(email))
		if not user:
			return None, "Invalid verification request. Account not found."
		if user.role not in {User.ROLE_CLIENT, User.ROLE_TENANT}:
			return None, "OTP verification is only applicable for Client and Tenant accounts."
		if user.email_verified:
			return {"message": "Email is already verified. You may now log in.", "email_verified": True}, None

		verified, error = user.verify_otp(otp)
		if not verified:
			db.session.commit()
			return None, error
		now = datetime.now(timezone.utc)
		user.is_active = True
		db.session.add(EmailVerificationHistory(
			user_id=user.id, requested_at=now, verified_at=now,
			status=EmailVerificationHistory.STATUS_VERIFIED,
			ip_address=ip_address, user_agent=user_agent,
		))
		db.session.commit()
		send_email(GraphEmailService.send_welcome_email, user)
		return {"message": "Email verified successfully! You can now log in.", "email_verified": True, "user": user.to_dict()}, None

	@staticmethod
	def resend_email_otp(email: str, ip_address: str | None = None, user_agent: str | None = None):
		valid, message = validate_email_format(email)
		if not valid:
			return None, message
		response = {"message": "If an unverified account exists for this email, a new 6-digit verification code has been sent."}
		user = UserRepository.get_by_email(normalize_email(email))
		if not user or user.role not in {User.ROLE_CLIENT, User.ROLE_TENANT} or user.email_verified:
			return response, None

		now = datetime.now(timezone.utc)
		if user.email_verification_otp_expires_at:
			seconds_left = (aware(user.email_verification_otp_expires_at) - now).total_seconds()
			if seconds_left > 270:
				return None, f"Please wait {int(seconds_left - 270)} seconds before requesting another code."

		EmailVerificationHistory.query.filter(
			EmailVerificationHistory.user_id == user.id,
			EmailVerificationHistory.status.in_([EmailVerificationHistory.STATUS_SENT, EmailVerificationHistory.STATUS_RESENT]),
		).update({EmailVerificationHistory.status: EmailVerificationHistory.STATUS_EXPIRED})
		otp = f"{secrets.randbelow(1_000_000):06d}"
		user.set_otp(otp)
		db.session.add(EmailVerificationHistory(
			user_id=user.id, requested_at=now, status=EmailVerificationHistory.STATUS_RESENT,
			ip_address=ip_address, user_agent=user_agent,
		))
		db.session.commit()
		send_email(GraphEmailService.send_otp_email, user, otp)
		return response, None

	@staticmethod
	def request_password_reset(email: str, ip_address: str | None = None, user_agent: str | None = None):
		valid, message = validate_email_format(email)
		if not valid:
			return None, message
		user = UserRepository.get_by_email(normalize_email(email))
		if not user:
			return None, "No account found with this email."
		if not user.is_active:
			return None, "This account is inactive. Please contact support."

		now = datetime.now(timezone.utc)
		raw_token = secrets.token_urlsafe(32)
		token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
		user.password_reset_token = token_hash
		user.password_reset_expires_at = now + timedelta(minutes=60)
		PasswordResetHistory.query.filter_by(
			user_id=user.id, status=PasswordResetHistory.STATUS_REQUESTED
		).update({PasswordResetHistory.status: PasswordResetHistory.STATUS_EXPIRED})
		history = PasswordResetHistory(
			user_id=user.id, requested_at=now, status=PasswordResetHistory.STATUS_REQUESTED,
			ip_address=ip_address, user_agent=user_agent,
		)
		db.session.add(history)
		db.session.commit()
		sent, _ = send_email(GraphEmailService.send_password_reset_email, user, raw_token, expiry_minutes=60)
		if not sent and user.password_reset_token == token_hash:
			history.status = PasswordResetHistory.STATUS_FAILED
			user.password_reset_token = None
			user.password_reset_expires_at = None
			db.session.commit()
		return {"message": "Password reset instructions have been sent to your email."}, None

	@staticmethod
	def reset_password(token: str, new_password: str, ip_address: str | None = None, user_agent: str | None = None):
		if not token or not token.strip():
			return False, "Password reset token is required."
		user = UserRepository.get_by_password_reset_token(hashlib.sha256(token.strip().encode("utf-8")).hexdigest())
		if not user or not user.is_active:
			return False, "Invalid or expired password reset link."

		now = datetime.now(timezone.utc)
		if not user.password_reset_expires_at or aware(user.password_reset_expires_at) < now:
			update_latest_reset(user.id, PasswordResetHistory.STATUS_EXPIRED)
			user.password_reset_token = None
			user.password_reset_expires_at = None
			db.session.commit()
			return False, "Password reset link has expired. Please request a new one."

		user.set_password(new_password)
		user.password_reset_token = None
		user.password_reset_expires_at = None
		user.token_version = (user.token_version or 1) + 1
		history = latest_reset(user.id)
		if history:
			history.status = PasswordResetHistory.STATUS_COMPLETED
			history.reset_at = now
		else:
			db.session.add(PasswordResetHistory(
				user_id=user.id, requested_at=now, reset_at=now,
				status=PasswordResetHistory.STATUS_COMPLETED,
				ip_address=ip_address, user_agent=user_agent,
			))
		db.session.commit()
		send_email(GraphEmailService.send_password_changed_email, user)
		return True, None