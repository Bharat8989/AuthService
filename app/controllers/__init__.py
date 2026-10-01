from app.controllers.auth_account_routes import auth_bp
from app.controllers.auth_profile_routes import users_bp
from app.controllers.admin_user_routes import admin_user_bp

__all__ = ["auth_bp", "users_bp", "admin_user_bp"]
