# User Service (Spring Boot, JWT, Google OAuth2, MySQL)

This sample project implements:
- Email/password registration & login (local users stored in MySQL)
- JWT issuance and JWT-based protection of endpoints
- Google OAuth2 login (creates local user record and issues JWT)
- Dockerfile + docker-compose (MySQL + app)

## Run locally with Docker Compose
```
docker-compose up --build
```

## Run locally from IntelliJ

Spring Boot does not load `.env` files automatically. This service imports the
module-root `.env` file through `spring.config.import`, so in the IntelliJ run
configuration set **Working directory** to the `user-service` module root (the
directory containing `pom.xml` and `.env`). Keep `.env` untracked; it is already
listed in `.gitignore`.

The file should use `KEY=value` entries for the required settings, including
`DB_URL`, `DB_USERNAME`, `DB_PASSWORD`, `JWT_SECRET`, `GOOGLE_CLIENT_ID`, and
`GOOGLE_CLIENT_SECRET`. Real environment variables set in IntelliJ or the
operating system continue to take precedence over values from `.env`.

## Endpoints
- POST /api/auth/register
- POST /api/auth/login
- GET  /api/protected (requires Authorization: Bearer <token>)
- GET  /oauth2/authorization/google  (start Google login)

After Google authentication succeeds, the service redirects to the frontend callback with the token in the URL fragment. Set `FRONTEND_OAUTH_CALLBACK_URL` to `http://localhost:5173/auth/callback` locally and to the deployed frontend callback URL in production.

The Google provider's registered redirect URI remains the user-service callback:
`{baseUrl}/login/oauth2/code/google`.

Set environment variables for secrets in production (DB credentials, JWT_SECRET, Google client id/secret).

Internal mail-service user-status API: `GET /api/v1/internal/users/{userId}/status`
returns the user ID and enabled flag (404 when absent) and requires the
`X-Internal-Api-Key` header. Set `USER_SERVICE_API_KEY` to the same secret in
this service and mail-service. Configure `USER_SERVICE_BASE_URL` in mail-service
to point to this service in each environment.

Internal user lookup by email: `GET /api/v1/internal/users/by-email?email={email}`
returns `id`, `email`, `provider`, `roles`, `enabled`, and `createdAt` (never the
password). It requires the `X-Internal-Api-Key` header and returns 404 when no
user matches.
