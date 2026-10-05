package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/** Signs access tokens. Only identity-auth holds the private key (07-api/authentication.md). */
public interface TokenIssuer {

    record IssuedToken(String token, long expiresInSeconds) { }

    IssuedToken issue(User user, Instant now);

    /** A client's token carrying the barbershop they picked, with its own lifetime (DEC-AUTH-06). */
    IssuedToken issueBound(User client, UUID barbershopId, Instant now, Duration lifetime);
}
