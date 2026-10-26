package co.edu.corhuila.barbersaas.identityauth.application.port.in;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.util.List;
import java.util.UUID;

/** What identity-auth offers (auth-service.yaml). */
public interface AuthUseCases {

    record RegisterCommand(String fullName, String email, String password, String phone) { }

    /** {@code created} is false when the same Idempotency-Key is retried: 200 instead of 201. */
    record AuthResult(String accessToken, String refreshToken, long expiresIn, User user, boolean created) { }

    record CreateOwnerCommand(String fullName, String email, String password, String phone, UUID barbershopId) { }

    /** An account created by someone else: no tokens. {@code created} is false on a retry (200 instead of 201). */
    record Created(User user, boolean created) { }

    /** The account is unverified and a code goes to its e-mail; no tokens until it is confirmed (DEC-AUTH-09). */
    Created register(RegisterCommand command, String idempotencyKey);

    /** Step create-owner of the owner-onboarding saga (DEC-AUTH-04). */
    Created createOwner(CreateOwnerCommand command, String idempotencyKey);

    record CreateBarberCommand(String fullName, String email, String password, String phone) { }

    /** An owner adds a barber to their barbershop, taken from the owner's token (DEC-AUTH-05). */
    Created createBarber(CreateBarberCommand command, UUID ownerBarbershopId, String idempotencyKey);

    AuthResult login(String email, String password);

    /** HU-AUTH-005: rotates the refresh token (single use) and issues a new access token. */
    AuthResult refresh(String refreshToken);

    /** HU-AUTH-005: revokes one session, or every session of the user with {@code allDevices}. */
    void logout(UUID userId, String refreshToken, boolean allDevices);

    /** DEC-AUTH-09: verifies the account with the e-mailed code and signs it in. */
    AuthResult confirmEmail(String email, String code);

    /** DEC-AUTH-09: a new code for an unverified account, within the limits; silent otherwise. */
    void resendVerification(String email);

    /** HU-AUTH-006: the account of the token. */
    User me(UUID userId);

    /** HU-AUTH-006: a null field is left as it is; an empty phone removes it. */
    User updateMe(UUID userId, String fullName, String phone, boolean phoneSent);

    /** HU-AUTH-006: needs the current password; every other session is closed. */
    void changePassword(UUID userId, String currentPassword, String newPassword, String keepRefreshToken);

    /** A token with role CLIENT and {@code barbershopId}; no refresh token (DEC-AUTH-06). */
    record BarbershopToken(String accessToken, long expiresIn, UUID barbershopId) { }

    /** Binds a client to the barbershop they picked, once it is checked to be open (DEC-AUTH-06). */
    BarbershopToken issueBarbershopToken(UUID clientId, UUID barbershopId);

    /** Another service checks a user and copies its display data (DEC-AUTH-07, ADR-014). */
    User findUser(UUID id);

    /** The owners platform-admin warns about the plan of their barbershop (DEC-AUTH-10). */
    List<User> findOwners(UUID barbershopId);

    /** No user with that id: 404. */
    class UserNotFound extends RuntimeException {
        public UserNotFound() {
            super("The user does not exist");
        }
    }

    /** Does not exist, is SUSPENDED or CANCELLED: 404, the same for the three. */
    class BarbershopNotFound extends RuntimeException {
        public BarbershopNotFound() {
            super("The barbershop does not exist");
        }
    }

    /** 403: the password is right but the e-mail is not verified yet (DEC-AUTH-09). */
    class EmailNotVerified extends RuntimeException {
        public EmailNotVerified() {
            super("Verify your e-mail before signing in");
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
