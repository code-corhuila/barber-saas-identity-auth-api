package co.edu.corhuila.barbersaas.identityauth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/** Reads the e-mailed verification code from the outbox, as notifications would, and confirms it (ADR-018). */
final class Verification {

    private Verification() {
    }

    /** The newest pending EmailVerificationRequested code of {@code email}. Needs the keys of InternalHttpTest. */
    static String code(MockMvc http, ObjectMapper json, String email) throws Exception {
        String worker = InternalHttpTest.token("barber-saas-worker", "SERVICE", null);
        String body = http.perform(get("/internal/v1/outbox-events?limit=100")
                        .header("Authorization", "Bearer " + worker))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String code = null;
        for (JsonNode e : json.readTree(body).get("data")) {
            if ("EmailVerificationRequested".equals(e.get("type").asText())
                    && email.equalsIgnoreCase(e.get("payload").get("email").asText())) {
                code = e.get("payload").get("code").asText();
            }
        }
        if (code == null) {
            throw new AssertionError("no verification code for " + email);
        }
        return code;
    }

    /** Confirms the e-mailed code and returns the answer: the same tokens as login. */
    static JsonNode confirm(MockMvc http, ObjectMapper json, String email) throws Exception {
        String body = http.perform(post("/api/v1/auth/email-verification/confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"%s\",\"code\":\"%s\"}".formatted(email, code(http, json, email))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(body);
    }
}
