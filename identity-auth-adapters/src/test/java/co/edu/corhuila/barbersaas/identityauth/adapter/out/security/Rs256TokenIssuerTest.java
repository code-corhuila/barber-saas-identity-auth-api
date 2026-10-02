package co.edu.corhuila.barbersaas.identityauth.adapter.out.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.Rs256Verifier;
import co.edu.corhuila.barbersaas.identityauth.domain.model.Role;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class Rs256TokenIssuerTest {

    private static Rs256TokenIssuer issuer;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        issuer = new Rs256TokenIssuer(pem, "test-1", 86_400);
    }

    @Test
    void a_token_it_issues_is_accepted_by_the_verifier_every_service_uses() throws Exception {
        User user = new User(UUID.randomUUID(), null, "Maria", "maria@example.com", "hash", null, null,
                Role.CLIENT, true, Instant.now());
        Instant now = Instant.now();

        String token = issuer.issue(user, now).token();

        assertEquals(user.id().toString(), new Rs256Verifier(issuer.publicKeyPem()).verify(token, now));
    }

    @Test
    void an_expired_token_is_refused() {
        User user = new User(UUID.randomUUID(), null, "Maria", "maria@example.com", "hash", null, null,
                Role.CLIENT, true, Instant.now());
        Instant issued = Instant.parse("2026-01-01T00:00:00Z");
        String token = issuer.issue(user, issued).token();

        assertThrows(Rs256Verifier.InvalidTokenException.class,
                () -> new Rs256Verifier(issuer.publicKeyPem()).verify(token, issued.plusSeconds(90_000)));
    }

    @Test
    void the_jwks_publishes_an_rs256_signing_key() {
        assertEquals("RS256", issuer.jwk().get("alg"));
        assertEquals("sig", issuer.jwk().get("use"));
        assertEquals("test-1", issuer.jwk().get("kid"));
    }
}
