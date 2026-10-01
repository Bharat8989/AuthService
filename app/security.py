import re

from flask_jwt_extended import create_access_token, create_refresh_token


EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$"
)


def validate_email_format(email: str) -> tuple[bool, str]:
    if not isinstance(email, str) or not email.strip():
        return False, "Email address is required."
    email = email.strip()
    if len(email) > 255 or not EMAIL_REGEX.fullmatch(email):
        return False, "Invalid email address format."
    return True, ""


def normalize_email(email: str | None) -> str:
    return email.strip().lower() if isinstance(email, str) else ""


def validate_password_strength(password: str) -> tuple[bool, str]:
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    return True, ""


def validate_phone_format(phone: str | None) -> tuple[bool, str | None]:
    if phone is None or phone == "":
        return True, None
    if not re.fullmatch(r"\+?[0-9\s\-]{7,20}", str(phone)):
        return False, "Invalid phone number format."
    return True, None


def generate_token_pair(user) -> dict[str, str]:
    token_version = getattr(user, "token_version", 1) or 1
    common_claims = {
        "role": user.role,
        "client_id": user.client_id,
        "token_version": token_version,
    }
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            **common_claims,
            "name": user.name,
            "email": user.email,
        },
    )
    refresh_token = create_refresh_token(
        identity=str(user.id), additional_claims=common_claims
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
    }