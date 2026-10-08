# Changelog

All notable changes to `barber-saas-identity-auth-api` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-08

MVP 2 (corte 2): first release of this repository to `main`, promoted from `develop` through `qa`
with `git cherry-pick -x` (norm 10–11).

User stories: code-corhuila/barber-saas-docs#3, code-corhuila/barber-saas-docs#6, code-corhuila/barber-saas-docs#7, code-corhuila/barber-saas-docs#59, code-corhuila/barber-saas-docs#76.

### Added

- **domain:** add the four user roles and which ones need a barbershop
- **domain:** add the business rule violation raised by the domain
- **domain:** enforce the password policy of the contract
- **domain:** add the user aggregate with its invariants
- **application:** declare the register and login use cases
- **application:** declare the user repository port with idempotency keys
- **application:** declare the password, token and id ports
- **application:** register clients idempotently and log users in
- **persistence:** generate identifiers in the service
- **persistence:** add an in-memory user repository for runs without a database
- **persistence:** store users and idempotency keys in one transaction
- **security:** hash passwords with bcrypt
- **security:** issue opaque refresh tokens stored only as a hash
- **security:** sign access tokens with rs256 and publish the jwk
- **security:** verify rs256 tokens with the public key
- **http:** add the shared error envelope
- **http:** turn every error into one status code and the envelope
- **http:** reuse or create the correlation id and log one line per request
- **http:** answer the liveness probe without a token
- **http:** validate the bearer token on protected routes
- **http:** expose register, login and the jwks
- **app:** add the spring boot entry point
- **app:** wire every port to its adapter with explicit pool limits
- **app:** set timeouts, graceful shutdown and json logs
- **deploy:** build the image and compose the service on the shared instance
- **http:** answer forbidden operations with 403 and the envelope
- **http:** read the caller's role and tenant and protect internal routes
- **usecase:** create the owner of a new barbershop once per saga step
- **http:** add POST /internal/v1/owners for the onboarding saga
- **usecase:** let an owner add barbers to their own barbershop
- **http:** add POST /api/v1/auth/barbers for owners
- **usecase:** issue a client token bound to an open barbershop
- **security:** sign a client token bound to a barbershop
- **http-client:** ask barbershop-api whether a barbershop is open
- **http:** add POST /api/v1/auth/barbershop-token for clients
- **internal:** add GET /internal/v1/users/{id} for barbershop
- **core:** reset a password with an e-mailed code
- **persistence:** relay the identity-auth outbox to the worker
- **http:** add password reset and the outbox relay operations

### Documentation

- **readme:** explain the service, how to run and test it, and what is missing
- **readme:** list the internal owner operation
- **readme:** list the barber account operation
- **readme:** list the barbershop-token operation
- **readme:** list the internal user read
- **readme:** point the header to Barber Saas and barber-saas-docs

### Tests

- **ci:** build and test every pull request with java 21
- **domain:** cover the tenant, e-mail and name invariants of the user
- **application:** cover registration, retries, duplicates and login with fake ports
- **security:** check issued tokens with the verifier every service uses
- **app:** check the http contract with the in-memory repository
- **usecase:** specify the client token bound to a barbershop
- **http:** specify POST /api/v1/auth/barbershop-token
- **internal:** specify the internal read of a user
- **http:** specify password reset through the outbox

### Maintenance

- **build:** ignore build output, ide files, env files and keys
- **github:** add the pull request template
- **github:** track the story environment on the board
- **build:** add the maven parent on spring boot 3.5 and java 21
- **build:** add the core module without any framework dependency
- **build:** add the adapters module with spring web, jdbc and bcrypt
- **build:** add the app module that composes the service
- **env:** list every variable without real values
- use the new repository name barber-saas-infra-postgres

[2.0.0]: https://github.com/code-corhuila/barber-saas-identity-auth-api/releases/tag/v2.0.0
