from datetime import datetime, timedelta, timezone

from app.extensions import db


class TokenBlocklist(db.Model):
	__tablename__ = "token_blocklist"

	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	jti = db.Column(db.String(36), nullable=False, unique=True, index=True)
	token_type = db.Column(db.String(10), nullable=False)
	user_id = db.Column(
		db.Integer,
		db.ForeignKey("users.id", ondelete="CASCADE"),
		nullable=False,
		index=True,
	)
	revoked_at = db.Column(
		db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
	)
	expires_at = db.Column(db.DateTime, nullable=False)

	user = db.relationship(
		"User", backref=db.backref("revoked_tokens", cascade="all, delete-orphan")
	)

	@classmethod
	def is_token_revoked(cls, jti: str) -> bool:
		return bool(jti) and db.session.query(cls.id).filter_by(jti=jti).first() is not None

	@classmethod
	def revoke_token(
		cls,
		jti: str,
		token_type: str,
		user_id: int,
		expires_at: datetime | None = None,
	) -> None:
		if not jti or cls.query.filter_by(jti=jti).first():
			return
		expires_at = expires_at or datetime.now(timezone.utc) + timedelta(days=7)
		db.session.add(
			cls(
				jti=jti,
				token_type=token_type,
				user_id=user_id,
				expires_at=expires_at,
			)
		)
		db.session.commit()
