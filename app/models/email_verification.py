from datetime import datetime, timezone

from app.extensions import db


class EmailVerificationHistory(db.Model):
	__tablename__ = "email_verification_history"

	STATUS_SENT = "SENT"
	STATUS_RESENT = "RESENT"
	STATUS_VERIFIED = "VERIFIED"
	STATUS_EXPIRED = "EXPIRED"
	STATUS_FAILED = "FAILED"
	VALID_STATUSES = {
		STATUS_SENT,
		STATUS_RESENT,
		STATUS_VERIFIED,
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
	verified_at = db.Column(db.DateTime, nullable=True)
	status = db.Column(db.String(20), nullable=False, default=STATUS_SENT)
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
		"User", backref=db.backref("email_verification_history", cascade="all, delete-orphan")
	)
