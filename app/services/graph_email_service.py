import html
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import current_app


logger = logging.getLogger(__name__)


class GraphEmailService:
    _token = None
    _token_expires_at = 0

    @classmethod
    def _access_token(cls) -> str | None:
        now = time.time()
        if cls._token and cls._token_expires_at > now + 300:
            return cls._token

        tenant_id = current_app.config.get("GRAPH_TENANT_ID")
        client_id = current_app.config.get("GRAPH_CLIENT_ID")
        client_secret = current_app.config.get("GRAPH_CLIENT_SECRET")
        if not all((tenant_id, client_id, client_secret)):
            logger.warning("Microsoft Graph email is not configured.")
            return None

        body = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"https://login.microsoftonline.com/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=current_app.config.get("GRAPH_TIMEOUT_SECONDS", 15),
            ) as response:
                result = json.loads(response.read().decode("utf-8"))
            cls._token = result.get("access_token")
            cls._token_expires_at = now + int(result.get("expires_in", 3600))
            return cls._token
        except Exception as exc:
            logger.error("Could not acquire Microsoft Graph access token: %s", exc)
            return None

    @classmethod
    def send_email(cls, user, subject: str, html_body: str) -> tuple[bool, str | None]:
        recipient = (user.email or "").strip().lower()
        sender = current_app.config.get("GRAPH_SENDER_EMAIL")
        access_token = cls._access_token()
        if not recipient or not sender or not access_token:
            return False, "Microsoft Graph email is not configured or recipient is missing."

        payload = {
            "message": {
                "subject": subject,
                "body": {"contentType": "HTML", "content": html_body},
                "toRecipients": [{"emailAddress": {"address": recipient}}],
            },
            "saveToSentItems": False,
        }
        request = urllib.request.Request(
            "https://graph.microsoft.com/v1.0/users/"
            + urllib.parse.quote(sender, safe="")
            + "/sendMail",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        retries = max(1, int(current_app.config.get("GRAPH_MAX_RETRIES", 3)))
        timeout = int(current_app.config.get("GRAPH_TIMEOUT_SECONDS", 15))
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(request, timeout=timeout):
                    return True, None
            except urllib.error.HTTPError as exc:
                retryable = exc.code == 429 or exc.code >= 500
                if not retryable or attempt + 1 == retries:
                    logger.error("Microsoft Graph email failed with HTTP %s.", exc.code)
                    return False, f"Microsoft Graph returned HTTP {exc.code}."
                retry_after = exc.headers.get("Retry-After", "")
                delay = min(max(int(retry_after), 1), 60) if retry_after.isdigit() else min(2**attempt, 10)
                time.sleep(delay)
            except Exception as exc:
                if attempt + 1 == retries:
                    logger.error("Microsoft Graph email delivery failed: %s", exc)
                    return False, "Microsoft Graph email delivery failed."
                time.sleep(min(2**attempt, 10))
        return False, "Microsoft Graph email delivery failed."

    @classmethod
    def send_otp_email(cls, user, otp: str, expiry_minutes: int = 5):
        name = html.escape((user.name or "User").strip())
        safe_otp = html.escape(otp.strip())
        subject = f"{safe_otp} is your PG Management System verification code"
        body = (
            f"<p>Hello {name},</p><p>Your verification code is "
            f"<strong>{safe_otp}</strong>.</p><p>It expires in {expiry_minutes} minutes.</p>"
        )
        return cls.send_email(user, subject, body)

    @classmethod
    def send_verification_email(cls, user, token: str, expiry_minutes: int = 60):
        link = (
            current_app.config["FRONTEND_URL"]
            + "/verify-email?token="
            + urllib.parse.quote(token)
        )
        name = html.escape((user.name or "User").strip())
        safe_link = html.escape(link, quote=True)
        body = (
            f"<p>Hello {name},</p><p><a href=\"{safe_link}\">Verify email</a></p>"
            f"<p>This link expires in {expiry_minutes} minutes.</p>"
        )
        return cls.send_email(user, "Verify Your PG Management System Account", body)

    @classmethod
    def send_password_reset_email(cls, user, token: str, expiry_minutes: int = 60):
        link = (
            current_app.config["FRONTEND_URL"]
            + "/reset-password?token="
            + urllib.parse.quote(token)
        )
        name = html.escape((user.name or "User").strip())
        safe_link = html.escape(link, quote=True)
        body = (
            f"<p>Hello {name},</p><p><a href=\"{safe_link}\">Reset password</a></p>"
            f"<p>This link expires in {expiry_minutes} minutes.</p>"
        )
        return cls.send_email(user, "Reset Your PG Management System Password", body)

    @classmethod
    def send_password_changed_email(cls, user):
        name = html.escape((user.name or "User").strip())
        return cls.send_email(
            user,
            "Your PG Management System Password Was Changed",
            f"<p>Hello {name}, your password was changed. If this was not you, contact support.</p>",
        )

    @classmethod
    def send_welcome_email(cls, user):
        name = html.escape((user.name or "User").strip())
        login_link = html.escape(current_app.config["FRONTEND_URL"] + "/login", quote=True)
        return cls.send_email(
            user,
            "Welcome to PG Management System!",
            f"<p>Hello {name}, your email is verified. <a href=\"{login_link}\">Log in</a>.</p>",
        )