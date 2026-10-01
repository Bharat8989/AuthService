import logging
from datetime import datetime, timezone

from app.models.email_verification import EmailVerificationHistory
from app.models.password_reset import PasswordResetHistory

logger = logging.getLogger(__name__)


def aware(value: datetime) -> datetime:
	return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def send_email(sender, user, *args, **kwargs) -> tuple[bool, str | None]:
	try:
		return sender(user, *args, **kwargs)
	except Exception:
		logger.exception("Auth email dispatch failed for user_id=%s", user.id)
		return False, "Email dispatch failed."


def latest_verification(user_id: int):
	return EmailVerificationHistory.query.filter_by(user_id=user_id).order_by(
		EmailVerificationHistory.created_at.desc()
	).first()


def update_latest_verification(user_id: int, status: str) -> None:
	history = latest_verification(user_id)
	if history:
		history.status = status


def latest_reset(user_id: int):
	return PasswordResetHistory.query.filter_by(
		user_id=user_id, status=PasswordResetHistory.STATUS_REQUESTED
	).order_by(PasswordResetHistory.created_at.desc()).first()


def update_latest_reset(user_id: int, status: str) -> None:
	history = latest_reset(user_id)
	if history:
		history.status = status