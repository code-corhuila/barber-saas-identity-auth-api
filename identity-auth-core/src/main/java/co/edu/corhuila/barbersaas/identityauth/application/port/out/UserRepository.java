package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.util.Optional;
import java.util.UUID;

/** Persistence of identity_auth.app_user and its idempotency keys. */
public interface UserRepository {

    record IdempotencyRecord(String key, String operation, String requestHash) { }

    record StoredKey(UUID resourceId, String requestHash) { }

    Optional<User> findByEmail(String normalizedEmail);

    Optional<User> findById(UUID id);

    Optional<StoredKey> findKey(String key, String operation);

    /** Writes the user and its idempotency key in ONE transaction. */
    void saveNew(User user, IdempotencyRecord key);

    /** Raised when the unique e-mail index rejects a concurrent registration. */
    class EmailAlreadyTaken extends RuntimeException {
        public EmailAlreadyTaken() {
            super("The email is already registered");
        }
    }
}
