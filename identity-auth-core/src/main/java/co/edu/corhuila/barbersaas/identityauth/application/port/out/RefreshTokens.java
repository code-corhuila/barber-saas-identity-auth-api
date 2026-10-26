package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Opaque refresh tokens: returned once in clear, stored only as a hash. */
public interface RefreshTokens {

    String issueFor(UUID userId, Instant now);

    /** Single use: a valid token is revoked and its user returned; any other one gives empty (HU-AUTH-005). */
    Optional<UUID> use(String token, Instant now);

    /** Logout of one session; a token of another user, or an unknown one, changes nothing. */
    void revoke(UUID userId, String token, Instant now);

    /** Every session of the user except the one of {@code keep}, if given (password change, all devices). */
    void revokeAll(UUID userId, String keep, Instant now);
}
