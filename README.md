# barber-saas-identity-auth-api

> identity-auth bounded context: service API

Part of the **LMS Library** distributed system — team `lms-library`, Grupo 2.
Governance and documentation live in [`library-docs`](https://github.com/code-corhuila/library-docs).

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

Full policy: `00-governance/branching-policy.md` in `library-docs`.

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
| `POST /api/v1/auth/barbers` | Role `ADMIN_BARBERSHOP`; creates a `BARBER` in the barbershop of the owner's token (never from the body) with an initial password; 201, or 200 on a retry; 403 for any other role; 422 if the e-mail exists |
| `POST /internal/v1/owners` | Only the workflow's service token (`sub: barber-saas-workflow`), never routed by the gateway; creates the `ADMIN_BARBERSHOP` of a barbershop the onboarding saga just created; 201, or 200 on a retry; 403 for any other token; 422 if the e-mail exists |
| `GET /health` | liveness, no token |

### How to start it

As part of the platform: `./scripts/up.sh dev` in `barber-saas-infra`. Alone, without a
database (in-memory repository):

```bash
mvn -B -DskipTests package
JWT_PRIVATE_KEY="$(cat ../barber-saas-infra/keys/jwt-private.pem)" java -jar identity-auth-app/target/identity-auth-app-0.1.0.jar
```

### Where the data is

Schema `identity_auth` of the shared PostgreSQL instance, as `identity_auth_app`
(`DATABASE_URL`, `DATABASE_USER`, `DATABASE_PASSWORD`; see `.env.example`). Passwords are stored
only as BCrypt hashes; refresh tokens only as SHA-256.

### How it is tested

`mvn -B verify` (no Docker needed): domain and use cases with fake ports, the token issuer
against the verifier, and the HTTP contract with the in-memory repository.

### What is missing

`refresh`, `logout` and `password-reset` from `auth-service.yaml`; the login lock of DEC-AUTH-02;
publishing `UserRegistered` through the outbox.
