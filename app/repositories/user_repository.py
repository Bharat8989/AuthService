from sqlalchemy import func

from app.extensions import db
from app.models.user import User


class UserRepository:
    @staticmethod
    def get_by_id(user_id: int) -> User | None:
        return db.session.get(User, user_id)

    @staticmethod
    def get_by_email(email: str) -> User | None:
        clean_email = (email or "").strip().lower()
        if not clean_email:
            return None
        return User.query.filter(func.lower(func.trim(User.email)) == clean_email).first()

    @staticmethod
    def get_by_phone(phone: str | None) -> User | None:
        clean_phone = phone.strip() if phone else None
        if not clean_phone:
            return None
        return User.query.filter_by(phone=clean_phone).first()

    @staticmethod
    def get_by_phone_excluding_user(phone: str, user_id: int) -> User | None:
        if not phone:
            return None
        return User.query.filter(User.phone == phone.strip(), User.id != user_id).first()

    @staticmethod
    def get_by_verification_token(token: str) -> User | None:
        return User.query.filter_by(verification_token=token.strip()).first() if token else None

    @staticmethod
    def get_by_password_reset_token(token_hash: str) -> User | None:
        return User.query.filter_by(password_reset_token=token_hash).first() if token_hash else None

    @staticmethod
    def create(user: User) -> User:
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def update(user: User) -> User:
        db.session.commit()
        return user