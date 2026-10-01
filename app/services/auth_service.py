import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.email_verification import EmailVerificationHistory
from app.models.password_reset import PasswordResetHistory
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.security import (
    generate_token_pair,
    normalize_email,
    validate_email_format,
    validate_password_strength,
)
from app.services.graph_email_service import GraphEmailService


logger = logging.getLogger(__name__)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class AuthService:
    @staticmethod
    def register_tenant(data: dict) -> tuple[dict | None, str | None]:
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
            name=data["name"].strip(),
            email=email,
            phone=phone.strip() if phone else None,
            role=User.ROLE_TENANT,
            client_id=None,
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
            logger.exception("Tenant registration failed.")
            return None, "Registration failed. Please try again."

        AuthService._send_email(GraphEmailService.send_otp_email, user, otp)
        result = user.to_dict()
        result["needs_email_verification"] = True
        return result, None

    @staticmethod
    def register_client(data: dict) -> tuple[None, str]:
        # Client creation and its cross-database saga belong to Client Service.
        return None, (
            "Client Service integration is required to register a client organization. "
            "No Auth user was created."
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
    def verify_email(
        token: str, ip_address: str | None = None, user_agent: str | None = None
    ) -> tuple[dict | None, str | None]:
        if not token or not token.strip():
            return None, "Verification token is required."
        user = UserRepository.get_by_verification_token(token.strip())
        if not user:
            return None, "Invalid or expired verification token."

        now = datetime.now(timezone.utc)
        if user.verification_token_expires_at and _aware(user.verification_token_expires_at) < now:
            AuthService._update_latest_verification(user.id, EmailVerificationHistory.STATUS_EXPIRED)
            user.verification_token = None
            user.verification_token_expires_at = None
            db.session.commit()
            return None, "Verification token has expired. Please request a new verification link."

        user.email_verified = True
        user.email_verified_at = now
        user.verification_token = None
        user.verification_token_expires_at = None
        history = AuthService._latest_verification(user.id)
        if history:
            history.status = EmailVerificationHistory.STATUS_VERIFIED
            history.verified_at = now
        else:
            db.session.add(
                EmailVerificationHistory(
                    user_id=user.id,
                    requested_at=now,
                    verified_at=now,
                    status=EmailVerificationHistory.STATUS_VERIFIED,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            )
        db.session.commit()
        AuthService._send_email(GraphEmailService.send_welcome_email, user)
        return {"message": "Email verified successfully. You can now log in."}, None

    @staticmethod
    def resend_verification(
        email: str, ip_address: str | None = None, user_agent: str | None = None
    ) -> tuple[dict | None, str | None]:
        valid, message = validate_email_format(email)
        if not valid:
            return None, message
        normalized = normalize_email(email)
        response = {
            "message": "If an unverified account exists for this email, a new verification link has been sent."
        }
        user = UserRepository.get_by_email(normalized)
        if not user or not user.is_active or user.email_verified:
            return response, None

        now = datetime.now(timezone.utc)
        token = secrets.token_urlsafe(32)
        user.verification_token = token
        user.verification_token_expires_at = now + timedelta(minutes=60)
        db.session.add(
            EmailVerificationHistory(
                user_id=user.id,
                requested_at=now,
                status=EmailVerificationHistory.STATUS_SENT,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        db.session.commit()
        AuthService._send_email(
            GraphEmailService.send_verification_email, user, token, expiry_minutes=60
        )
        return response, None

    @staticmethod
    def verify_email_otp(
        email: str,
        otp: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[dict | None, str | None]:
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
        db.session.add(
            EmailVerificationHistory(
                user_id=user.id,
                requested_at=now,
                verified_at=now,
                status=EmailVerificationHistory.STATUS_VERIFIED,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        db.session.commit()
        AuthService._send_email(GraphEmailService.send_welcome_email, user)
        return {
            "message": "Email verified successfully! You can now log in.",
            "email_verified": True,
            "user": user.to_dict(),
        }, None

    @staticmethod
    def resend_email_otp(
        email: str, ip_address: str | None = None, user_agent: str | None = None
    ) -> tuple[dict | None, str | None]:
        valid, message = validate_email_format(email)
        if not valid:
            return None, message
        normalized = normalize_email(email)
        response = {
            "message": "If an unverified account exists for this email, a new 6-digit verification code has been sent."
        }
        user = UserRepository.get_by_email(normalized)
        if not user or user.role not in {User.ROLE_CLIENT, User.ROLE_TENANT} or user.email_verified:
            return response, None

        now = datetime.now(timezone.utc)
        expires_at = user.email_verification_otp_expires_at
        if expires_at:
            seconds_left = (_aware(expires_at) - now).total_seconds()
            if seconds_left > 270:
                return None, f"Please wait {int(seconds_left - 270)} seconds before requesting another code."

        EmailVerificationHistory.query.filter(
            EmailVerificationHistory.user_id == user.id,
            EmailVerificationHistory.status.in_(
                [EmailVerificationHistory.STATUS_SENT, EmailVerificationHistory.STATUS_RESENT]
            ),
        ).update({EmailVerificationHistory.status: EmailVerificationHistory.STATUS_EXPIRED})
        otp = f"{secrets.randbelow(1_000_000):06d}"
        user.set_otp(otp)
        db.session.add(
            EmailVerificationHistory(
                user_id=user.id,
                requested_at=now,
                status=EmailVerificationHistory.STATUS_RESENT,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        db.session.commit()
        AuthService._send_email(GraphEmailService.send_otp_email, user, otp)
        return response, None

    @staticmethod
    def request_password_reset(
        email: str, ip_address: str | None = None, user_agent: str | None = None
    ) -> tuple[dict | None, str | None]:
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
            user_id=user.id,
            requested_at=now,
            status=PasswordResetHistory.STATUS_REQUESTED,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.session.add(history)
        db.session.commit()

        sent, _ = AuthService._send_email(
            GraphEmailService.send_password_reset_email,
            user,
            raw_token,
            expiry_minutes=60,
        )
        if not sent and user.password_reset_token == token_hash:
            history.status = PasswordResetHistory.STATUS_FAILED
            user.password_reset_token = None
            user.password_reset_expires_at = None
            db.session.commit()
        return {"message": "Password reset instructions have been sent to your email."}, None

    @staticmethod
    def reset_password(
        token: str,
        new_password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[bool, str | None]:
        if not token or not token.strip():
            return False, "Password reset token is required."
        token_hash = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
        user = UserRepository.get_by_password_reset_token(token_hash)
        if not user or not user.is_active:
            return False, "Invalid or expired password reset link."

        now = datetime.now(timezone.utc)
        if not user.password_reset_expires_at or _aware(user.password_reset_expires_at) < now:
            AuthService._update_latest_reset(user.id, PasswordResetHistory.STATUS_EXPIRED)
            user.password_reset_token = None
            user.password_reset_expires_at = None
            db.session.commit()
            return False, "Password reset link has expired. Please request a new one."

        user.set_password(new_password)
        user.password_reset_token = None
        user.password_reset_expires_at = None
        user.token_version = (user.token_version or 1) + 1
        history = AuthService._latest_reset(user.id)
        if history:
            history.status = PasswordResetHistory.STATUS_COMPLETED
            history.reset_at = now
        else:
            db.session.add(
                PasswordResetHistory(
                    user_id=user.id,
                    requested_at=now,
                    reset_at=now,
                    status=PasswordResetHistory.STATUS_COMPLETED,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            )
        db.session.commit()
        AuthService._send_email(GraphEmailService.send_password_changed_email, user)
        return True, None

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
                db.session.add(
                    EmailVerificationHistory(
                        user_id=user.id,
                        status=EmailVerificationHistory.STATUS_SENT,
                    )
                )
            else:
                otp = None
        else:
            otp = None
        if "phone" in data:
            phone = data["phone"].strip() if data["phone"] else None
            duplicate_phone = UserRepository.get_by_phone_excluding_user(phone, user.id) if phone else None
            if duplicate_phone:
                return None, "This phone number is already in use by another account."
            user.phone = phone
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return None, "Email or phone number is already in use."
        if otp:
            AuthService._send_email(GraphEmailService.send_otp_email, user, otp)
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
        AuthService._send_email(GraphEmailService.send_password_changed_email, user)
        return True, None

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

    @staticmethod
    def _send_email(sender, user, *args, **kwargs) -> tuple[bool, str | None]:
        try:
            return sender(user, *args, **kwargs)
        except Exception:
            logger.exception("Auth email dispatch failed for user_id=%s", user.id)
            return False, "Email dispatch failed."

    @staticmethod
    def _latest_verification(user_id: int):
        return EmailVerificationHistory.query.filter_by(user_id=user_id).order_by(
            EmailVerificationHistory.created_at.desc()
        ).first()

    @staticmethod
    def _update_latest_verification(user_id: int, status: str) -> None:
        history = AuthService._latest_verification(user_id)
        if history:
            history.status = status

    @staticmethod
    def _latest_reset(user_id: int):
        return PasswordResetHistory.query.filter_by(
            user_id=user_id, status=PasswordResetHistory.STATUS_REQUESTED
        ).order_by(PasswordResetHistory.created_at.desc()).first()

    @staticmethod
    def _update_latest_reset(user_id: int, status: str) -> None:
        history = AuthService._latest_reset(user_id)
        if history:
            history.status = status