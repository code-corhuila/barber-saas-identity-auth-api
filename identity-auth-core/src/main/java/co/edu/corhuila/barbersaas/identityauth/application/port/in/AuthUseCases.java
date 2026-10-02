package co.edu.corhuila.barbersaas.identityauth.application.port.in;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;

/** What identity-auth offers (auth-service.yaml). */
public interface AuthUseCases {

    record RegisterCommand(String fullName, String email, String password, String phone) { }

    /** {@code created} is false when the same Idempotency-Key is retried: 200 instead of 201. */
    record AuthResult(String accessToken, String refreshToken, long expiresIn, User user, boolean created) { }

    AuthResult register(RegisterCommand command, String idempotencyKey);

    AuthResult login(String email, String password);

    /** 401, with the same message whether the e-mail, the password or the account failed. */
    class InvalidCredentials extends RuntimeException {
        public InvalidCredentials() {
            super("Incorrect email or password");
        }
    }

    /** The same Idempotency-Key with a different body: 422. */
    class IdempotencyKeyReused extends RuntimeException {
        public IdempotencyKeyReused() {
            super("The Idempotency-Key was already used with a different request");
        }
    }
}
