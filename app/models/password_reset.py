from datetime import datetime, timezone

from app.extensions import db


class PasswordResetHistory(db.Model):
	__tablename__ = "password_reset_history"

	STATUS_REQUESTED = "REQUESTED"
	STATUS_COMPLETED = "COMPLETED"
	STATUS_EXPIRED = "EXPIRED"
	STATUS_FAILED = "FAILED"
	VALID_STATUSES = {
		STATUS_REQUESTED,
		STATUS_COMPLETED,
		STATUS_EXPIRED,
		STATUS_FAILED,
	}

	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	user_id = db.Column(
		db.Integer,
		db.ForeignKey("users.id", ondelete="CASCADE"),
		nullable=False,
		index=True,
	)
	requested_at = db.Column(
		db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
	)
	reset_at = db.Column(db.DateTime, nullable=True)
	status = db.Column(db.String(20), nullable=False, default=STATUS_REQUESTED)
	ip_address = db.Column(db.String(50), nullable=True)
	user_agent = db.Column(db.String(255), nullable=True)
	created_at = db.Column(
		db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
	)
	updated_at = db.Column(
		db.DateTime,
		nullable=False,
		default=lambda: datetime.now(timezone.utc),
		onupdate=lambda: datetime.now(timezone.utc),
	)

	user = db.relationship(
		"User", backref=db.backref("password_reset_history", cascade="all, delete-orphan")
	)
