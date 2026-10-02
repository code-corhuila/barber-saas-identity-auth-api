package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import java.time.Instant;
import java.util.UUID;

/** Opaque refresh tokens: returned once in clear, stored only as a hash. */
public interface RefreshTokens {

    String issueFor(UUID userId, Instant now);
}
