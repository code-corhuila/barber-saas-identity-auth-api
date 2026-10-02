package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.time.Instant;

/** Signs access tokens. Only identity-auth holds the private key (07-api/authentication.md). */
public interface TokenIssuer {

    record IssuedToken(String token, long expiresInSeconds) { }

    IssuedToken issue(User user, Instant now);
}
