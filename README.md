# barber-saas-identity-auth-api

> identity-auth bounded context: service API

Part of the **Barber Saas** distributed system — team `barber-saas`, Grupo 2.
Governance and documentation live in [`barber-saas-docs`](https://github.com/code-corhuila/barber-saas-docs).

## Branching

Three permanent branches. **None of them accepts a direct commit** — you enter through a child
branch and leave through a Pull Request.

```
develop  <--PR--  feat/... fix/... chore/...
qa       <--PR--  qa/...
main     <--PR--  release/...  hotfix/...
```

Promotion happens **by re-application** (`git cherry-pick -x`), never by merging one permanent
branch into another: `merge develop -> qa` and `merge qa -> main` do not exist in this model.

`main` requires **1 approval from `ariel5253`**. On `develop` and `qa` the team sets its own review
rule.

Full policy: `00-governance/branching-policy.md` in `barber-saas-docs`.

---

## BarberSaaS — what this repository is

The identity service: registers client accounts, logs users in, issues RS256 access tokens and
publishes the public key (JWKS) every other service validates with (07-api/authentication.md).
Hexagonal, three Maven modules (ADR-012, annex C): `identity-auth-core` (domain and use cases,
no Spring), `identity-auth-adapters` (HTTP, JDBC, BCrypt, RS256) and `identity-auth-app`
(composition root). It never migrates its schema: that is `barber-saas-identity-auth-db`.

| Operation | Contract |
|---|---|
| `POST /api/v1/auth/register` | `Idempotency-Key` required; 201, or 200 on a retry; 422 if the e-mail exists |
| `POST /api/v1/auth/login` | 200 with tokens; 401 with the same message for any wrong credential |
| `GET /api/v1/auth/jwks` | RFC 7517 key set |
| `POST /api/v1/auth/password-reset` | Always 202 (`DEC-AUTH-03`); for an active account it stores a 6-digit code as a hash (15 minutes, the earlier codes stop working) and writes `PasswordResetRequested` to the outbox in the same transaction (`DEC-AUTH-08`) |
| `POST /api/v1/auth/password-reset/confirm` | 204: marks the code used, sets the new password and revokes every refresh token of the user; 422 with one message for a wrong, expired or used code |
| `POST /api/v1/auth/barbers` | Role `ADMIN_BARBERSHOP`; creates a `BARBER` in the barbershop of the owner's token (never from the body) with an initial password; 201, or 200 on a retry; 403 for any other role; 422 if the e-mail exists |
| `POST /api/v1/auth/barbershop-token` | Role `CLIENT`; body `{barbershopId}`; checks the barbershop is `ACTIVE` or `TRIAL` with barbershop-api (`BARBERSHOP_API_URL`) and returns a one-hour `CLIENT` token with that `barbershopId`, no refresh token, nothing stored (`DEC-AUTH-06`); 403 for any other role; 404 if closed or unknown; 503 if barbershop-api does not answer |
| `POST /internal/v1/owners` | Only the workflow's service token (`sub: barber-saas-workflow`), never routed by the gateway; creates the `ADMIN_BARBERSHOP` of a barbershop the onboarding saga just created; 201, or 200 on a retry; 403 for any other token; 422 if the e-mail exists |
| `GET /internal/v1/outbox-events`, `POST .../{id}/published`, `POST .../{id}/failed` | Only the worker's service token (`sub: barber-saas-worker`), never routed by the gateway (ADR-016); `published` also removes `code` from the row; 403 for any other token; 404 for an unknown id |
| `GET /internal/v1/users/{id}` | Only barbershop-api's service token (`sub: barber-saas-barbershop-api`), never routed by the gateway; returns `id`, `fullName`, `profilePhotoUrl`, `role`, `barbershopId`, `isActive` — never the e-mail, phone or hash (`DEC-AUTH-07`, ADR-014); 403 for any other token; 404 if unknown |
| `GET /health` | liveness, no token |

### How to start it

As part of the platform: `./scripts/up.sh dev` in `barber-saas-infra-postgres`. Alone, without a
database (in-memory repository); without `BARBERSHOP_API_URL`,
`POST /api/v1/auth/barbershop-token` answers 503:

```bash
mvn -B -DskipTests package
JWT_PRIVATE_KEY="$(cat ../barber-saas-infra-postgres/keys/jwt-private.pem)" java -jar identity-auth-app/target/identity-auth-app-0.1.0.jar
```

### Where the data is

Schema `identity_auth` of the shared PostgreSQL instance, as `identity_auth_app`
(`DATABASE_URL`, `DATABASE_USER`, `DATABASE_PASSWORD`; see `.env.example`). Passwords are stored
only as BCrypt hashes, and so are reset codes; refresh tokens only as SHA-256.

### How it is tested

`mvn -B verify` (no Docker needed): domain and use cases with fake ports, the token issuer
against the verifier, and the HTTP contract with the in-memory repository.

### What is missing

`refresh` and `logout` from `auth-service.yaml`; the login lock of DEC-AUTH-02;
publishing `UserRegistered` through the outbox.
