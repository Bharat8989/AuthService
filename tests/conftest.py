import pytest

from app import create_app
from app.extensions import db
from app.models.user import User


@pytest.fixture
def app():
    application = create_app(
        "testing",
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": "test-jwt-secret-not-for-production",
            "SECRET_KEY": "test-flask-secret-not-for-production",
            "RATELIMIT_ENABLED": False,
            "GRAPH_TENANT_ID": None,
            "GRAPH_CLIENT_ID": None,
            "GRAPH_CLIENT_SECRET": None,
            "GRAPH_SENDER_EMAIL": None,
        },
    )
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def users(app):
    with app.app_context():
        records = {}
        roles = [
            ("superadmin", User.ROLE_SUPERADMIN, None),
            ("client", User.ROLE_CLIENT, 101),
            ("admin", User.ROLE_ADMIN, 101),
            ("tenant", User.ROLE_TENANT, None),
        ]
        for index, (name, role, client_id) in enumerate(roles, start=1):
            user = User(
                name=name.title(),
                email=f"{name}@example.test",
                role=role,
                client_id=client_id,
                client_status="active" if client_id else None,
                is_active=True,
                email_verified=True,
            )
            user.set_password("Password123!")
            db.session.add(user)
            db.session.flush()
            records[name] = user.id
        db.session.commit()
        return records