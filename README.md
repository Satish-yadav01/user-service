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

## Endpoints
- POST /api/auth/register
- POST /api/auth/login
- GET  /api/protected (requires Authorization: Bearer <token>)
- GET  /oauth2/authorization/google  (start Google login)

Set environment variables for secrets in production (DB credentials, JWT_SECRET, Google client id/secret).
