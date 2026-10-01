from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from flask_jwt_extended import decode_token
from werkzeug.security import check_password_hash

from app import create_app
from app.extensions import db
from app.models.password_reset import PasswordResetHistory
from app.models.token_blocklist import TokenBlocklist
from app.models.user import User
from app.services.auth_service import AuthService
from app.services.graph_email_service import GraphEmailService


@pytest.mark.parametrize(
    ("role", "client_id"),
    [
        ("superadmin", None),
        ("client", 101),
        ("admin", 101),
        ("tenant", None),
    ],
)
def test_login_emits_existing_role_claims(client, app, users, role, client_id):
    response = client.post(
        "/api/auth/login",
        json={"email": f"{role}@example.test", "password": "Password123!"},
    )
    assert response.status_code == 200
    with app.app_context():
        claims = decode_token(response.json["data"]["tokens"]["access_token"])
    assert claims["role"] == role
    assert claims["client_id"] == client_id
    assert claims["sub"] == str(users[role])
    token = response.json["data"]["tokens"]["access_token"]
    profile = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert profile.status_code == 200


def test_login_rejects_wrong_password(client, users):
    response = client.post(
        "/api/auth/login",
        json={"email": "tenant@example.test", "password": "WrongPassword123"},
    )
    assert response.status_code == 401
    assert response.json["error_code"] == "AUTH_FAILED"


def test_tenant_registration_stores_only_password_and_otp_hash(client, app):
    with patch.object(GraphEmailService, "send_otp_email", return_value=(True, None)):
        response = client.post(
            "/api/auth/register",
            json={
                "name": "New Tenant",
                "email": "newtenant@example.test",
                "phone": None,
                "password": "SecurePass123",
            },
        )
    assert response.status_code == 201
    assert response.json["data"]["needs_email_verification"] is True
    with app.app_context():
        user = User.query.filter_by(email="newtenant@example.test").one()
        assert user.password_hash != "SecurePass123"
        assert user.check_password("SecurePass123")
        assert user.email_verification_otp_hash
        assert "email_verification_otp_hash" not in response.json["data"]


def test_duplicate_registration_is_rejected_and_role_is_not_request_assignable(client, app):
    payload = {
        "name": "New Tenant",
        "email": "duplicate@example.test",
        "phone": None,
        "password": "SecurePass123",
        "role": "superadmin",
    }
    with patch.object(GraphEmailService, "send_otp_email", return_value=(True, None)):
        first = client.post("/api/auth/register", json=payload)
        second = client.post("/api/auth/register", json=payload)
    assert first.status_code == 201
    assert first.json["data"]["role"] == "tenant"
    assert second.status_code == 409


def test_inactive_user_cannot_login(client, app, users):
    with app.app_context():
        user = db.session.get(User, users["tenant"])
        user.is_active = False
        db.session.commit()
    response = client.post(
        "/api/auth/login",
        json={"email": "tenant@example.test", "password": "Password123!"},
    )
    assert response.status_code == 403


def test_register_client_creates_auth_user_and_sends_verification(client, app):
    with patch.object(GraphEmailService, "send_otp_email", return_value=(True, None)) as send_otp:
        response = client.post(
            "/api/auth/register-client",
            json={
                "company_name": "Example Client",
                "owner_name": "Owner Example",
                "email": "owner@example.test",
                "phone": None,
                "password": "SecurePass123",
            },
        )
    assert response.status_code == 201
    assert response.json["data"]["needs_email_verification"] is True
    assert response.json["data"]["role"] == "client"
    assert send_otp.call_count == 1
    with app.app_context():
        user = User.query.filter_by(email="owner@example.test").one()
        assert user.name == "Owner Example"
        assert user.role == User.ROLE_CLIENT
        assert user.client_id is None
        assert user.check_password("SecurePass123")


def test_me_returns_identity_without_fabricated_client_data(client, app, users):
    login = client.post(
        "/api/auth/login",
        json={"email": "client@example.test", "password": "Password123!"},
    )
    token = login.json["data"]["tokens"]["access_token"]
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json["data"]["client_id"] == 101
    assert "client" not in response.json["data"]


def test_refresh_rotation_revokes_previous_refresh_token(client, users):
    login = client.post(
        "/api/auth/login",
        json={"email": "tenant@example.test", "password": "Password123!"},
    )
    old_refresh = login.json["data"]["tokens"]["refresh_token"]
    rotated = client.post(
        "/api/auth/refresh", headers={"Authorization": f"Bearer {old_refresh}"}
    )
    assert rotated.status_code == 200
    reused = client.post(
        "/api/auth/refresh", headers={"Authorization": f"Bearer {old_refresh}"}
    )
    assert reused.status_code == 401
    assert reused.json["error_code"] == "TOKEN_REVOKED"


def test_logout_revokes_supplied_refresh_token(client, users):
    login = client.post(
        "/api/auth/login",
        json={"email": "tenant@example.test", "password": "Password123!"},
    )
    refresh = login.json["data"]["tokens"]["refresh_token"]
    assert client.post("/api/auth/logout", json={"refresh_token": refresh}).status_code == 200
    revoked = client.post(
        "/api/auth/refresh", headers={"Authorization": f"Bearer {refresh}"}
    )
    assert revoked.status_code == 401


def test_reset_password_hashes_new_password_and_invalidates_old_tokens(client, app, users):
    login = client.post(
        "/api/auth/login",
        json={"email": "tenant@example.test", "password": "Password123!"},
    )
    access = login.json["data"]["tokens"]["access_token"]
    with patch.object(
        GraphEmailService, "send_password_reset_email", return_value=(True, None)
    ) as send_reset:
        requested = client.post(
            "/api/auth/forgot-password", json={"email": "tenant@example.test"}
        )
    assert requested.status_code == 200
    raw_token = send_reset.call_args.args[1]
    completed = client.post(
        "/api/auth/reset-password",
        json={"token": raw_token, "password": "NewPassword456"},
    )
    assert completed.status_code == 200
    replayed = client.post(
        "/api/auth/reset-password",
        json={"token": raw_token, "password": "AnotherPassword789"},
    )
    assert replayed.status_code == 400
    with app.app_context():
        user = User.query.filter_by(email="tenant@example.test").one()
        assert user.check_password("NewPassword456")
        assert user.password_hash != "NewPassword456"
        assert user.password_reset_token is None
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code == 401


def test_otp_verification_is_single_use_and_expires(client, app):
    with patch.object(GraphEmailService, "send_otp_email", return_value=(True, None)):
        client.post(
            "/api/auth/register",
            json={
                "name": "OTP Tenant",
                "email": "otp@example.test",
                "phone": None,
                "password": "SecurePass123",
            },
        )
    with app.app_context():
        user = User.query.filter_by(email="otp@example.test").one()
        user.set_otp("123456")
        db.session.commit()
        assert check_password_hash(user.email_verification_otp_hash, "123456")
    verify = client.post(
        "/api/auth/verify-email-otp",
        json={"email": "otp@example.test", "otp": "123456"},
    )
    assert verify.status_code == 200, verify.get_json()
    reused = client.post(
        "/api/auth/verify-email-otp",
        json={"email": "otp@example.test", "otp": "123456"},
    )
    assert reused.status_code == 200
    assert reused.json["data"]["email_verified"] is True


def test_otp_attempt_limit_clears_otp(client, app):
    with patch.object(GraphEmailService, "send_otp_email", return_value=(True, None)):
        client.post(
            "/api/auth/register",
            json={
                "name": "OTP Tenant",
                "email": "attempts@example.test",
                "phone": None,
                "password": "SecurePass123",
            },
        )
    with app.app_context():
        user = User.query.filter_by(email="attempts@example.test").one()
        user.set_otp("123456")
        db.session.commit()
    for _ in range(5):
        response = client.post(
            "/api/auth/verify-email-otp",
            json={"email": "attempts@example.test", "otp": "000000"},
        )
    assert response.status_code == 400
    with app.app_context():
        user = User.query.filter_by(email="attempts@example.test").one()
        assert user.email_verification_otp_hash is None


def test_expired_otp_fails(client, app):
    with patch.object(GraphEmailService, "send_otp_email", return_value=(True, None)):
        client.post(
            "/api/auth/register",
            json={
                "name": "OTP Tenant",
                "email": "expired@example.test",
                "phone": None,
                "password": "SecurePass123",
            },
        )
    with app.app_context():
        user = User.query.filter_by(email="expired@example.test").one()
        user.set_otp("123456")
        user.email_verification_otp_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()
    response = client.post(
        "/api/auth/verify-email-otp",
        json={"email": "expired@example.test", "otp": "123456"},
    )
    assert response.status_code == 400


def test_resend_otp_enforces_cooldown(client, app):
    with patch.object(GraphEmailService, "send_otp_email", return_value=(True, None)):
        client.post(
            "/api/auth/register",
            json={
                "name": "OTP Tenant",
                "email": "cooldown@example.test",
                "phone": None,
                "password": "SecurePass123",
            },
        )
        response = client.post(
            "/api/auth/resend-email-otp", json={"email": "cooldown@example.test"}
        )
    assert response.status_code == 400
    assert "wait" in response.json["message"].lower()


def test_graph_failure_does_not_expose_otp_or_reset_token(client, app):
    with patch.object(GraphEmailService, "send_otp_email", return_value=(False, "offline")):
        registered = client.post(
            "/api/auth/register",
            json={
                "name": "No Mail Tenant",
                "email": "nomail@example.test",
                "phone": None,
                "password": "SecurePass123",
            },
        )
    assert registered.status_code == 201
    assert "email_verification_otp_hash" not in registered.text
    with app.app_context():
        user = User.query.filter_by(email="nomail@example.test").one()
        user.email_verified = True
        db.session.commit()
    recipient_emails = []

    def fail_reset_email(user, *_args, **_kwargs):
        recipient_emails.append(user.email)
        return False, "offline"

    with patch.object(
        GraphEmailService, "send_password_reset_email", side_effect=fail_reset_email
    ):
        response = client.post(
            "/api/auth/forgot-password", json={"email": "nomail@example.test"}
        )
    assert response.status_code == 200
    assert recipient_emails == ["nomail@example.test"]
    with app.app_context():
        user = User.query.filter_by(email="nomail@example.test").one()
        assert user.password_reset_token is None
        assert PasswordResetHistory.query.filter_by(
            user_id=user.id, status=PasswordResetHistory.STATUS_FAILED
        ).first()


def test_password_change_invalidates_previous_access_token(client, users):
    login = client.post(
        "/api/auth/login",
        json={"email": "tenant@example.test", "password": "Password123!"},
    )
    access = login.json["data"]["tokens"]["access_token"]
    changed = client.patch(
        "/api/users/me/password",
        headers={"Authorization": f"Bearer {access}"},
        json={"current_password": "Password123!", "new_password": "Changed456!"},
    )
    assert changed.status_code == 200
    old_token = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {access}"}
    )
    assert old_token.status_code == 401


def test_client_status_missing_fails_closed(client, app):
    with app.app_context():
        user = User(
            name="Unprovisioned Client",
            email="missing-status@example.test",
            role=User.ROLE_CLIENT,
            client_id=202,
            client_status=None,
            is_active=True,
            email_verified=True,
        )
        user.set_password("Password123!")
        db.session.add(user)
        db.session.commit()
    response = client.post(
        "/api/auth/login",
        json={"email": "missing-status@example.test", "password": "Password123!"},
    )
    assert response.status_code == 503


def test_email_verification_link_is_single_use(client, app):
    with patch.object(GraphEmailService, "send_otp_email", return_value=(True, None)):
        client.post(
            "/api/auth/register",
            json={
                "name": "Link Tenant",
                "email": "link@example.test",
                "phone": None,
                "password": "SecurePass123",
            },
        )
    with patch.object(
        GraphEmailService, "send_verification_email", return_value=(True, None)
    ) as send_verification:
        resent = client.post(
            "/api/auth/resend-verification", json={"email": "link@example.test"}
        )
    assert resent.status_code == 200
    verification_token = send_verification.call_args.args[1]
    verified = client.post(
        "/api/auth/verify-email", json={"token": verification_token}
    )
    assert verified.status_code == 200
    reused = client.post(
        "/api/auth/verify-email", json={"token": verification_token}
    )
    assert reused.status_code == 400


def test_sync_superadmin_is_explicit_and_hashes_password(app, monkeypatch):
    monkeypatch.setenv("SUPERADMIN_EMAIL", "root@example.test")
    monkeypatch.setenv("SUPERADMIN_PASSWORD", "SuperSecret123")
    with app.app_context():
        success, _message = AuthService.sync_superadmin_logic()
        assert success
        user = User.query.filter_by(role=User.ROLE_SUPERADMIN).one()
        assert user.email == "root@example.test"
        assert user.check_password("SuperSecret123")
        assert user.password_hash != "SuperSecret123"


def test_auth_login_rate_limit():
    limited_app = create_app(
        "testing",
        {"RATELIMIT_ENABLED": True, "RATELIMIT_STORAGE_URI": "memory://"},
    )
    with limited_app.app_context():
        db.create_all()
    client = limited_app.test_client()
    responses = [
        client.post(
            "/api/auth/login",
            json={"email": "missing@example.test", "password": "WrongPassword123"},
        )
        for _ in range(11)
    ]
    assert all(response.status_code == 401 for response in responses[:10])
    assert responses[-1].status_code == 429
    with limited_app.app_context():
        db.session.remove()
        db.drop_all()