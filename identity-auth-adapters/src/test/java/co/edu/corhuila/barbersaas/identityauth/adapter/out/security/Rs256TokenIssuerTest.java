package co.edu.corhuila.barbersaas.identityauth.adapter.out.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.Caller;
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

        Caller caller = new Rs256Verifier(issuer.publicKeyPem()).verify(token, now);
        assertEquals(user.id().toString(), caller.subject());
        assertEquals("CLIENT", caller.role());
        assertNull(caller.barbershopId());
    }

    @Test
    void the_verifier_reads_the_tenant_of_barbershop_staff() throws Exception {
        UUID barbershop = UUID.randomUUID();
        User owner = new User(UUID.randomUUID(), barbershop, "Andres", "andres@example.com", "hash", null, null,
                Role.ADMIN_BARBERSHOP, true, Instant.now());
        Instant now = Instant.now();

        Caller caller = new Rs256Verifier(issuer.publicKeyPem()).verify(issuer.issue(owner, now).token(), now);

        assertTrue(caller.hasRole("ADMIN_BARBERSHOP"));
        assertEquals(barbershop, caller.barbershopId());
        assertFalse(caller.isService("barber-saas-workflow"));
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
