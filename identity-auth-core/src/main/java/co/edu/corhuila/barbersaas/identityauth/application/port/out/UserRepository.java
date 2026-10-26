package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Persistence of identity_auth.app_user and its idempotency keys. */
public interface UserRepository {

    record IdempotencyRecord(String key, String operation, String requestHash) { }

    record StoredKey(UUID resourceId, String requestHash) { }

    Optional<User> findByEmail(String normalizedEmail);

    Optional<User> findById(UUID id);

    /** The active ADMIN_BARBERSHOP accounts of one barbershop, oldest first (DEC-AUTH-10). */
    List<User> findActiveOwners(UUID barbershopId);

    Optional<StoredKey> findKey(String key, String operation);

    /** Name, phone and password hash of an existing user (HU-AUTH-006). */
    void update(User user, Instant now);

    /** Writes the user and its idempotency key in ONE transaction. */
    void saveNew(User user, IdempotencyRecord key);

    /** Raised when the unique e-mail index rejects a concurrent registration. */
    class EmailAlreadyTaken extends RuntimeException {
        public EmailAlreadyTaken() {
            super("The email is already registered");
        }
    }
}
