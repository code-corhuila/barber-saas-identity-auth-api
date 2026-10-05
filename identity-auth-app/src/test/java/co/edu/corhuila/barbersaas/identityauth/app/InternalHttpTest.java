package co.edu.corhuila.barbersaas.identityauth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** POST /internal/v1/owners (auth-service.yaml, DEC-AUTH-04), with real RS256 tokens. */
@SpringBootTest
@AutoConfigureMockMvc
class InternalHttpTest {

    private static final KeyPair KEYS = keyPair();

    @Autowired
    private MockMvc http;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(KEYS.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        registry.add("JWT_PRIVATE_KEY", () -> pem);
        registry.add("BCRYPT_STRENGTH", () -> "4");
    }

    @Test
    void the_workflow_creates_an_owner_once_per_saga_step() throws Exception {
        String body = owner("andres@example.com", UUID.randomUUID());

        http.perform(createOwner(token("barber-saas-workflow", "SERVICE", null), "saga-0001:create-owner", body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("ADMIN_BARBERSHOP"))
                .andExpect(jsonPath("$.barbershopId").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        http.perform(createOwner(token("barber-saas-workflow", "SERVICE", null), "saga-0001:create-owner", body))
                .andExpect(status().isOk());
    }

    @Test
    void a_user_token_is_forbidden_even_for_an_owner() throws Exception {
        String owner = token(UUID.randomUUID().toString(), "ADMIN_BARBERSHOP", UUID.randomUUID());

        http.perform(createOwner(owner, "saga-0002:create-owner", owner("x@example.com", UUID.randomUUID())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("FORBIDDEN"));
    }

    @Test
    void another_service_is_forbidden() throws Exception {
        http.perform(createOwner(token("barber-saas-worker", "SERVICE", null), "saga-0003:create-owner",
                        owner("y@example.com", UUID.randomUUID())))
                .andExpect(status().isForbidden());
    }

    @Test
    void without_a_token_it_is_401() throws Exception {
        http.perform(post("/internal/v1/owners").header("Idempotency-Key", "saga-0004:create-owner")
                        .contentType(MediaType.APPLICATION_JSON).content(owner("z@example.com", UUID.randomUUID())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void a_missing_barbershop_is_a_field_error() throws Exception {
        http.perform(createOwner(token("barber-saas-workflow", "SERVICE", null), "saga-0005:create-owner",
                        """
                        {"fullName":"Andres Rojas","email":"w@example.com","password":"SecurePass123"}
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("barbershopId"));
    }

    @Test
    void an_email_already_registered_is_422() throws Exception {
        String workflow = token("barber-saas-workflow", "SERVICE", null);
        http.perform(createOwner(workflow, "saga-0006:create-owner", owner("taken@example.com", UUID.randomUUID())))
                .andExpect(status().isCreated());

        http.perform(createOwner(workflow, "saga-0007:create-owner", owner("taken@example.com", UUID.randomUUID())))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("BUSINESS_RULE_VIOLATION"));
    }

    private static org.springframework.test.web.servlet.RequestBuilder createOwner(String token, String key,
                                                                                    String body) {
        return post("/internal/v1/owners").header("Authorization", "Bearer " + token)
                .header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String owner(String email, UUID barbershopId) {
        return """
                {"fullName":"Andres Rojas","email":"%s","password":"SecurePass123","barbershopId":"%s"}
                """.formatted(email, barbershopId);
    }

    /** A token with the claims of 07-api/authentication.md, signed with the service's own key pair. */
    static String token(String subject, String role, UUID barbershopId) throws Exception {
        long now = Instant.now().getEpochSecond();
        String tenant = barbershopId == null ? "" : ",\"barbershopId\":\"" + barbershopId + "\"";
        String header = b64("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"dev-1\"}");
        String claims = b64("{\"iss\":\"barber-saas-identity-auth-api\",\"sub\":\"" + subject + "\",\"role\":\""
                + role + "\",\"iat\":" + now + ",\"exp\":" + (now + 600) + tenant + "}");
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(KEYS.getPrivate());
        rsa.update((header + "." + claims).getBytes(StandardCharsets.US_ASCII));
        return header + "." + claims + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(rsa.sign());
    }

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
