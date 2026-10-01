import re
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


class User(db.Model):
	__tablename__ = "users"

	ROLE_SUPERADMIN = "superadmin"
	ROLE_CLIENT = "client"
	ROLE_ADMIN = "admin"
	ROLE_TENANT = "tenant"
	VALID_ROLES = {ROLE_SUPERADMIN, ROLE_CLIENT, ROLE_ADMIN, ROLE_TENANT}

	CLIENT_STATUS_PENDING = "pending"
	CLIENT_STATUS_ACTIVE = "active"
	CLIENT_STATUS_SUSPENDED = "suspended"
	CLIENT_STATUS_INACTIVE = "inactive"
	INVALID_CLIENT_STATUSES = {CLIENT_STATUS_SUSPENDED, CLIENT_STATUS_INACTIVE}

	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	name = db.Column(db.String(255), nullable=False)
	email = db.Column(db.String(255), nullable=False, unique=True, index=True)
	phone = db.Column(db.String(50), nullable=True, unique=True)
	password_hash = db.Column(db.String(255), nullable=False)
	role = db.Column(db.String(20), nullable=False, default=ROLE_TENANT)
	client_id = db.Column(db.Integer, nullable=True, index=True)
	# Client Service maintains this auth-required status projection; it is not a Client ORM relation.
	client_status = db.Column(db.String(20), nullable=True)
	is_active = db.Column(db.Boolean, nullable=False, default=True)
	email_verified = db.Column(db.Boolean, nullable=False, default=False)
	verification_token = db.Column(db.String(255), nullable=True, index=True)
	verification_token_expires_at = db.Column(db.DateTime, nullable=True)
	password_reset_token = db.Column(db.String(64), nullable=True, index=True)
	password_reset_expires_at = db.Column(db.DateTime, nullable=True)
	email_verification_otp_hash = db.Column(db.String(255), nullable=True)
	email_verification_otp_expires_at = db.Column(db.DateTime, nullable=True)
	email_verification_attempts = db.Column(db.Integer, nullable=False, default=0)
	email_verified_at = db.Column(db.DateTime, nullable=True)
	token_version = db.Column(db.Integer, nullable=False, default=1)
	created_at = db.Column(
		db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
	)
	updated_at = db.Column(
		db.DateTime,
		nullable=False,
		default=lambda: datetime.now(timezone.utc),
		onupdate=lambda: datetime.now(timezone.utc),
	)

	def set_password(self, password: str) -> None:
		self.password_hash = generate_password_hash(password)

	def check_password(self, password: str) -> bool:
		return bool(self.password_hash) and check_password_hash(
			self.password_hash, password
		)

	def set_otp(self, raw_otp: str, expires_in_minutes: int = 5) -> None:
		self.email_verification_otp_hash = generate_password_hash(raw_otp.strip())
		self.email_verification_otp_expires_at = datetime.now(
			timezone.utc
		) + timedelta(minutes=expires_in_minutes)
		self.email_verification_attempts = 0
		self.verification_token = None
		self.verification_token_expires_at = None

	def verify_otp(self, raw_otp: str) -> tuple[bool, str | None]:
		if not self.email_verification_otp_hash or not self.email_verification_otp_expires_at:
			return False, "No active OTP verification found. Please request a new OTP."

		if self.email_verification_attempts >= 5:
			self._clear_otp()
			return False, "Maximum verification attempts exceeded. Please request a new OTP."

		expires_at = self.email_verification_otp_expires_at
		if expires_at.tzinfo is None:
			expires_at = expires_at.replace(tzinfo=timezone.utc)
		now = datetime.now(timezone.utc)
		if expires_at < now:
			self._clear_otp()
			return False, "OTP has expired. Please request a new OTP."

		if not check_password_hash(self.email_verification_otp_hash, raw_otp.strip()):
			self.email_verification_attempts += 1
			remaining = 5 - self.email_verification_attempts
			if remaining <= 0:
				self._clear_otp()
				return False, "Invalid OTP. Maximum attempts reached. Please request a new OTP."
			return False, f"Invalid OTP. {remaining} attempt(s) remaining."

		self._clear_otp()
		self.verification_token = None
		self.verification_token_expires_at = None
		self.email_verified = True
		self.email_verified_at = now
		return True, None

	def _clear_otp(self) -> None:
		self.email_verification_otp_hash = None
		self.email_verification_otp_expires_at = None
		self.email_verification_attempts = 0

	def to_dict(self) -> dict:
		return {
			"id": self.id,
			"name": self.name,
			"email": self.email,
			"phone": self.phone,
			"role": self.role,
			"client_id": self.client_id,
			"is_active": self.is_active,
			"email_verified": self.email_verified,
			"email_verified_at": (
				self.email_verified_at.isoformat() if self.email_verified_at else None
			),
			"created_at": self.created_at.isoformat() if self.created_at else None,
			"updated_at": self.updated_at.isoformat() if self.updated_at else None,
		}
