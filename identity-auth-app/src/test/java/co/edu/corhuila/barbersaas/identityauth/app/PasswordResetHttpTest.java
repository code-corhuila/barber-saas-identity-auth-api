package co.edu.corhuila.barbersaas.identityauth.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

/**
 * Password recovery end to end (HU-AUTH-002, DEC-AUTH-03, DEC-AUTH-08): the code reaches the worker
 * only through the outbox, and leaves the row once the event is published.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PasswordResetHttpTest {

    private static final KeyPair KEYS = keyPair();

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(KEYS.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        registry.add("JWT_PRIVATE_KEY", () -> pem);
        registry.add("BCRYPT_STRENGTH", () -> "4");
    }

    @Test
    void the_emailed_code_sets_a_new_password_once() throws Exception {
        register("laura@example.com");
        String worker = token("barber-saas-worker", "SERVICE");

        http.perform(reset("Laura@Example.com")).andExpect(status().isAccepted());
        JsonNode event = pendingEvent(worker, "laura@example.com");
        assertEquals(1, event.get("version").asInt());
        assertEquals("user", event.get("aggregateType").asText());
        String code = event.get("payload").get("code").asText();

        http.perform(confirm("laura@example.com", code.equals("000000") ? "111111" : "000000", "NewPass123"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message").value("The code is invalid or has expired"));
        http.perform(confirm("laura@example.com", code, "NewPass123")).andExpect(status().isNoContent());
        http.perform(confirm("laura@example.com", code, "Other12345")).andExpect(status().isUnprocessableEntity());

        http.perform(login("laura@example.com", "SecurePass123")).andExpect(status().isUnauthorized());
        http.perform(login("laura@example.com", "NewPass123")).andExpect(status().isOk());

        String id = event.get("id").asText();
        http.perform(post("/internal/v1/outbox-events/" + id + "/published").header("Authorization", "Bearer " + worker))
                .andExpect(status().isNoContent());
        http.perform(post("/internal/v1/outbox-events/" + id + "/published").header("Authorization", "Bearer " + worker))
                .andExpect(status().isNoContent());
        assertFalse(pending(worker).toString().contains(id));
    }

    @Test
    void an_unknown_email_is_accepted_and_writes_nothing() throws Exception {
        http.perform(reset("ghost@example.com")).andExpect(status().isAccepted());
        assertFalse(pending(token("barber-saas-worker", "SERVICE")).toString().contains("ghost@example.com"));
    }

    @Test
    void malformed_bodies_are_400() throws Exception {
        http.perform(post("/api/v1/auth/password-reset").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("email"));
        http.perform(confirm("laura@example.com", "12ab56", "NewPass123"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("code"));
    }

    @Test
    void only_the_worker_reads_and_confirms_the_outbox() throws Exception {
        http.perform(get("/internal/v1/outbox-events")).andExpect(status().isUnauthorized());
        http.perform(get("/internal/v1/outbox-events").header("Authorization",
                        "Bearer " + token("barber-saas-workflow", "SERVICE")))
                .andExpect(status().isForbidden());
        http.perform(get("/internal/v1/outbox-events").header("Authorization",
                        "Bearer " + token(UUID.randomUUID().toString(), "SUPER_ADMIN")))
                .andExpect(status().isForbidden());
    }

    @Test
    void a_failure_needs_a_reason_and_an_existing_event() throws Exception {
        register("pedro@example.com");
        String worker = token("barber-saas-worker", "SERVICE");
        http.perform(reset("pedro@example.com")).andExpect(status().isAccepted());
        String id = pendingEvent(worker, "pedro@example.com").get("id").asText();

        http.perform(failed(worker, id, "{\"reason\":\" \"}")).andExpect(status().isBadRequest());
        http.perform(failed(worker, UUID.randomUUID().toString(), "{\"reason\":\"notifications 422 X\"}"))
                .andExpect(status().isNotFound());
        http.perform(failed(worker, id, "{\"reason\":\"notifications 422 UNKNOWN_EVENT_TYPE\"}"))
                .andExpect(status().isNoContent());
        assertFalse(pending(worker).toString().contains(id));
    }

    private void register(String email) throws Exception {
        http.perform(post("/api/v1/auth/register").header("Idempotency-Key", "register-" + UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"fullName":"Laura Gomez","email":"%s","password":"SecurePass123"}
                                """.formatted(email)))
                .andExpect(status().isCreated());
    }

    private JsonNode pending(String worker) throws Exception {
        String body = http.perform(get("/internal/v1/outbox-events?limit=100").header("Authorization", "Bearer " + worker))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(body).get("data");
    }

    private JsonNode pendingEvent(String worker, String email) throws Exception {
        for (JsonNode e : pending(worker)) {
            if (email.equals(e.get("payload").get("email").asText())) {
                assertEquals("PasswordResetRequested", e.get("type").asText());
                assertTrue(e.get("payload").get("code").asText().matches("\\d{6}"));
                return e;
            }
        }
        throw new AssertionError("no pending event for " + email);
    }

    private static org.springframework.test.web.servlet.RequestBuilder reset(String email) {
        return post("/api/v1/auth/password-reset").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\"}");
    }

    private static org.springframework.test.web.servlet.RequestBuilder confirm(String email, String code,
                                                                                String password) {
        return post("/api/v1/auth/password-reset/confirm").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"%s\",\"code\":\"%s\",\"newPassword\":\"%s\"}".formatted(email, code, password));
    }

    private static org.springframework.test.web.servlet.RequestBuilder login(String email, String password) {
        return post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, password));
    }

    private static org.springframework.test.web.servlet.RequestBuilder failed(String worker, String id, String body) {
        return post("/internal/v1/outbox-events/" + id + "/failed").header("Authorization", "Bearer " + worker)
                .contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String token(String subject, String role) throws Exception {
        long now = Instant.now().getEpochSecond();
        String header = b64("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"dev-1\"}");
        String claims = b64("{\"iss\":\"barber-saas-identity-auth-api\",\"sub\":\"" + subject + "\",\"role\":\""
                + role + "\",\"iat\":" + now + ",\"exp\":" + (now + 600) + "}");
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(KEYS.getPrivate());
        rsa.update((header + "." + claims).getBytes(StandardCharsets.US_ASCII));
        return header + "." + claims + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(rsa.sign());
    }

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
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
