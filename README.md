# AuthService

Independent Flask service for user identity and authentication. It owns the
`pg_auth_service` database and has no ORM relationship to Client or business models.

## Setup

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set a private MySQL `DATABASE_URL` for `pg_auth_service`, strong independent
`SECRET_KEY` and `JWT_SECRET_KEY` values, and the Microsoft Graph settings
required for transactional auth email. Do not commit `.env`.

Create the database separately, then run the AuthService-owned migrations:

```powershell
venv\Scripts\python.exe -m flask --app app:create_app db upgrade
```

To explicitly create/synchronize the SuperAdmin from `SUPERADMIN_EMAIL` and
`SUPERADMIN_PASSWORD`, run:

```powershell
venv\Scripts\python.exe -m flask --app app:create_app sync-superadmin
```

SuperAdmin synchronization is never run at application startup. Start the
service with `venv\Scripts\python.exe run.py`; run focused tests with
`venv\Scripts\python.exe -m pytest -q tests`.

## Service Boundaries

- `client_id` is a nullable integer logical reference. AuthService does not
  query Client Service or create a cross-service ForeignKey.
- `client_status` is an Auth-owned status projection needed to preserve the
  existing suspended/inactive login check. A trusted Client Service
  provisioning/synchronization integration is not implemented yet. Client and
  admin login fails closed with `503` when the projection is missing.
- `POST /api/auth/register-client` creates an Auth user for the client owner,
  issues an OTP/email-verification flow, and leaves `client_id` unset until the
  separate Client Service provisioner acknowledges the organization. AuthService
  continues to guard against orphaned identity state by validating the owner
  record and verification step before login.
- `GET /api/auth/me` returns identity fields only. Client-specific profile data
  must be fetched/aggregated by a future API gateway or Client Service.
- Client/admin provisioning, Client owner profile synchronization, and
  SuperAdmin user management must call Auth identity APIs when those service
  integrations are implemented. No new internal HTTP API is exposed yet.
- Token blocklist and `token_version` checks are local to AuthService. A future
  gateway/consumer verification contract is required for immediate revocation
  across services; no distributed token architecture is implemented here.
## SuperAdmin Identity API

AuthService also exposes these JWT-protected routes for callers with the
`superadmin` role:

- `GET /api/internal/superadmin/users`
- `GET /api/internal/superadmin/users/<id>`
- `PATCH /api/internal/superadmin/users/<id>`
- `PATCH /api/internal/superadmin/users/<id>/status`
- `PATCH /api/internal/superadmin/users/<id>/block`
- `PATCH /api/internal/superadmin/users/<id>/unblock`

SuperAdminService uses these routes for identity changes. User deletion remains
owned by the service that can verify business-record dependencies.
