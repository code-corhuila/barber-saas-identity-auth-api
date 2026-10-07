package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Persistence of identity_auth.password_reset_token: the code is kept only as a hash. */
public interface PasswordResets {

    record ResetCode(UUID id, UUID userId, String codeHash, Instant expiresAt, Instant createdAt) { }

    /**
     * In ONE transaction: the earlier unused codes of the user stop working, the new code is stored
     * and the event that e-mails it is written to the outbox (DEC-AUTH-08).
     */
    void saveRequest(ResetCode code, OutboxEvent event);

    /** Codes of the user not used and not expired at {@code now}, newest first. */
    List<ResetCode> usable(UUID userId, Instant now);

    /**
     * In ONE transaction: marks the code used, stores the new password hash of {@code user} and revokes
     * every refresh token of the user. False when the code was used meanwhile (single use).
     */
    boolean consume(UUID codeId, User user, Instant now);
}
