import os
import secrets
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote_plus, unquote, urlsplit

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
	SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
	JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or secrets.token_urlsafe(32)
	MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
	MYSQL_PORT = os.getenv("MYSQL_PORT", "3306")
	MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "pg_auth_service")
	MYSQL_USER = os.getenv("MYSQL_USER", "root")
	MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
	DATABASE_URL = os.getenv("DATABASE_URL")
	SQLALCHEMY_DATABASE_URI = DATABASE_URL or (
		"mysql+pymysql://"
		f"{quote_plus(MYSQL_USER)}:{quote_plus(MYSQL_PASSWORD)}@"
		f"{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}?charset=utf8mb4"
	)
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	JWT_ACCESS_TOKEN_EXPIRES = timedelta(
		seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "900"))
	)
	JWT_REFRESH_TOKEN_EXPIRES = timedelta(
		seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", "604800"))
	)
	JWT_ERROR_MESSAGE_KEY = "message"
	JWT_TOKEN_LOCATION = ["headers"]
	CORS_ORIGINS = [
		origin.strip()
		for origin in os.getenv(
			"CORS_ALLOWED_ORIGINS",
			os.getenv("FRONTEND_URL", "http://localhost:5173"),
		).split(",")
		if origin.strip()
	]
	RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
	RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200/hour")
	RATELIMIT_HEADERS_ENABLED = True
	RATELIMIT_ENABLED = True
	FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
	GRAPH_TENANT_ID = os.getenv("GRAPH_TENANT_ID")
	GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID")
	GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET")
	GRAPH_SENDER_EMAIL = os.getenv("GRAPH_SENDER_EMAIL")
	GRAPH_TIMEOUT_SECONDS = int(os.getenv("GRAPH_TIMEOUT_SECONDS", "15"))
	GRAPH_MAX_RETRIES = int(os.getenv("GRAPH_MAX_RETRIES", "3"))
	REQUIRE_EMAIL_DISPATCH = os.getenv("REQUIRE_EMAIL_DISPATCH", "true").lower() in {
		"true",
		"1",
	}


class TestingConfig(Config):
	TESTING = True
	SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:")
	JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
	JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=1)
	RATELIMIT_ENABLED = False
	CORS_ORIGINS = "*"


class ProductionConfig(Config):
	DEBUG = False

	@classmethod
	def validate(cls):
		missing = [
			name
			for name in ("SECRET_KEY", "JWT_SECRET_KEY")
			if not os.getenv(name)
		]
		if missing:
			raise RuntimeError(
				f"Missing required production settings: {', '.join(missing)}"
			)
		if not cls.SQLALCHEMY_DATABASE_URI.startswith("mysql+pymysql://"):
			raise RuntimeError("Production DATABASE_URL must use MySQL via PyMySQL.")
		database_name = unquote(urlsplit(cls.SQLALCHEMY_DATABASE_URI).path.lstrip("/")).split("/")[-1]
		if database_name != "pg_auth_service":
			raise RuntimeError("AuthService DATABASE_URL must target pg_auth_service.")
		if cls.RATELIMIT_STORAGE_URI.startswith("memory://"):
			raise RuntimeError("Production rate limiting requires shared storage.")
		if not cls.CORS_ORIGINS or cls.CORS_ORIGINS == "*" or "*" in cls.CORS_ORIGINS:
			raise RuntimeError("Production CORS must list explicit allowed origins.")
		graph_settings = (
			"GRAPH_TENANT_ID",
			"GRAPH_CLIENT_ID",
			"GRAPH_CLIENT_SECRET",
			"GRAPH_SENDER_EMAIL",
		)
		missing_graph = [name for name in graph_settings if not os.getenv(name)]
		if missing_graph:
			raise RuntimeError(
				f"Missing required production Graph settings: {', '.join(missing_graph)}"
			)


CONFIG_BY_NAME = {
	"development": Config,
	"testing": TestingConfig,
	"production": ProductionConfig,
}
