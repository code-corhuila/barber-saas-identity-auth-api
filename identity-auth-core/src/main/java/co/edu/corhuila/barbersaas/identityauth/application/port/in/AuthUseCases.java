package co.edu.corhuila.barbersaas.identityauth.application.port.in;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.util.UUID;

/** What identity-auth offers (auth-service.yaml). */
public interface AuthUseCases {

    record RegisterCommand(String fullName, String email, String password, String phone) { }

    /** {@code created} is false when the same Idempotency-Key is retried: 200 instead of 201. */
    record AuthResult(String accessToken, String refreshToken, long expiresIn, User user, boolean created) { }

    record CreateOwnerCommand(String fullName, String email, String password, String phone, UUID barbershopId) { }

    /** An account created by someone else: no tokens. {@code created} is false on a retry (200 instead of 201). */
    record Created(User user, boolean created) { }

    AuthResult register(RegisterCommand command, String idempotencyKey);

    /** Step create-owner of the owner-onboarding saga (DEC-AUTH-04). */
    Created createOwner(CreateOwnerCommand command, String idempotencyKey);

    record CreateBarberCommand(String fullName, String email, String password, String phone) { }

    /** An owner adds a barber to their barbershop, taken from the owner's token (DEC-AUTH-05). */
    Created createBarber(CreateBarberCommand command, UUID ownerBarbershopId, String idempotencyKey);

    AuthResult login(String email, String password);

    /** A token with role CLIENT and {@code barbershopId}; no refresh token (DEC-AUTH-06). */
    record BarbershopToken(String accessToken, long expiresIn, UUID barbershopId) { }

    /** Binds a client to the barbershop they picked, once it is checked to be open (DEC-AUTH-06). */
    BarbershopToken issueBarbershopToken(UUID clientId, UUID barbershopId);

    /** Does not exist, is SUSPENDED or CANCELLED: 404, the same for the three. */
    class BarbershopNotFound extends RuntimeException {
        public BarbershopNotFound() {
            super("The barbershop does not exist");
        }
    }

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
