import logging
import os
from urllib.parse import unquote, urlsplit

from flask import Flask
from flask_limiter.errors import RateLimitExceeded
from werkzeug.exceptions import HTTPException

from app.config import CONFIG_BY_NAME
from app.extensions import cors, db, jwt, limiter, migrate
from app.responses import error_response


def create_app(config_name: str | None = None, test_config: dict | None = None) -> Flask:
	config_name = (config_name or os.getenv("FLASK_ENV", "development")).lower()
	config_class = CONFIG_BY_NAME.get(config_name, CONFIG_BY_NAME["development"])
	app = Flask(__name__)
	app.config.from_object(config_class)
	if test_config:
		app.config.update(test_config)

	if config_name == "production":
		config_class.validate()
	elif config_name != "testing":
		database_uri = app.config["SQLALCHEMY_DATABASE_URI"]
		if database_uri.startswith("mysql+pymysql://"):
			database_name = unquote(urlsplit(database_uri).path.lstrip("/")).split("/")[-1]
			if database_name != "pg_auth_service":
				raise RuntimeError("AuthService DATABASE_URL must target pg_auth_service.")

	logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
	app.logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

	db.init_app(app)
	migrate.init_app(app, db)
	jwt.init_app(app)
	limiter.init_app(app)

	origins = app.config.get("CORS_ORIGINS") or "*"
	cors.init_app(
		app,
		resources={r"/*": {"origins": origins}},
		supports_credentials=True,
	)

	from app import models  # noqa: F401
	from app.controllers.auth_controller import auth_bp, users_bp
	from app.commands.sync_superadmin import sync_superadmin_cli

	app.register_blueprint(auth_bp)
	app.register_blueprint(users_bp)
	app.cli.add_command(sync_superadmin_cli)

	_register_jwt_callbacks()

	@app.errorhandler(RateLimitExceeded)
	def handle_rate_limit(_error):
		return error_response(
			"Rate limit exceeded. Please try again later.",
			"TOO_MANY_REQUESTS",
			429,
		)

	@app.errorhandler(HTTPException)
	def handle_http_error(error):
		return error_response(
			error.description,
			error.name.upper().replace(" ", "_"),
			error.code or 500,
		)

	@app.errorhandler(Exception)
	def handle_unexpected_error(error):
		app.logger.exception("Unhandled Auth Service exception: %s", error)
		return error_response("An unexpected internal server error occurred.")

	return app


def _register_jwt_callbacks() -> None:
	@jwt.unauthorized_loader
	def unauthorized(message):
		return error_response(
			message or "Missing authorization token.", "UNAUTHORIZED", 401
		)

	@jwt.invalid_token_loader
	def invalid_token(message):
		return error_response(
			message or "Invalid authorization token.", "INVALID_TOKEN", 401
		)

	@jwt.expired_token_loader
	def expired_token(_header, _payload):
		return error_response("Token has expired.", "TOKEN_EXPIRED", 401)

	@jwt.revoked_token_loader
	def revoked_token(_header, _payload):
		return error_response("Token has been revoked.", "TOKEN_REVOKED", 401)

	@jwt.token_in_blocklist_loader
	def check_revocation(_header, payload):
		from app.models.token_blocklist import TokenBlocklist
		from app.repositories.user_repository import UserRepository

		jti = payload.get("jti")
		if jti and TokenBlocklist.is_token_revoked(jti):
			return True
		subject = payload.get("sub")
		token_version = payload.get("token_version")
		if not subject:
			return True
		try:
			user = UserRepository.get_by_id(int(subject))
		except (TypeError, ValueError):
			return True
		if not user or not user.is_active:
			return True
		if token_version is not None and (user.token_version or 1) > int(token_version):
			return True
		return False
