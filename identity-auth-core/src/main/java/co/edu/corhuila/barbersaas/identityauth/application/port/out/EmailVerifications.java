package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Persistence of identity_auth.email_verification_code (ADR-018): the code is kept only as a hash. */
public interface EmailVerifications {

    record VerificationCode(UUID id, UUID userId, String codeHash, Instant expiresAt, Instant createdAt) { }

    /**
     * In ONE transaction: the earlier unused codes of the user stop working, the new code is stored
     * and the event that e-mails it is written to the outbox (DEC-AUTH-09).
     */
    void saveVerification(VerificationCode code, OutboxEvent event);

    /** Codes of the user not used and not expired at {@code now}, newest first. */
    List<VerificationCode> usableVerifications(UUID userId, Instant now);

    /** How many codes the user was sent since {@code since}: the resend limits. */
    int verificationsSince(UUID userId, Instant since);

    /** In ONE transaction: marks the code used and the user verified. False when it was used meanwhile. */
    boolean consumeVerification(UUID codeId, UUID userId, Instant now);
}
