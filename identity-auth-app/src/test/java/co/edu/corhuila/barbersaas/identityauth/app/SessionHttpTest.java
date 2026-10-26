package co.edu.corhuila.barbersaas.identityauth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** HU-AUTH-004 to HU-AUTH-006 over HTTP (auth-service.yaml 3.0.0), with real RS256 tokens. */
@SpringBootTest
@AutoConfigureMockMvc
class SessionHttpTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
    }

    @Test
    void register_then_verify_then_sign_in() throws Exception {
        register("sofia@example.com");
        http.perform(login("sofia@example.com", "SecurePass123"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("FORBIDDEN"))
                .andExpect(jsonPath("$.message").value("Verify your e-mail before signing in"));
        http.perform(login("sofia@example.com", "WrongPass123")).andExpect(status().isUnauthorized());

        http.perform(confirm("sofia@example.com", "000000".equals(code("sofia@example.com")) ? "111111" : "000000"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message").value("The code is invalid or has expired"));
        JsonNode signedIn = Verification.confirm(http, json, "sofia@example.com");
        org.junit.jupiter.api.Assertions.assertTrue(signedIn.get("user").get("emailVerified").asBoolean());
        http.perform(login("sofia@example.com", "SecurePass123")).andExpect(status().isOk());
    }

    @Test
    void resend_always_answers_202() throws Exception {
        register("tomas@example.com");
        http.perform(resend("tomas@example.com")).andExpect(status().isAccepted());
        http.perform(resend("nobody@example.com")).andExpect(status().isAccepted());
        http.perform(post("/api/v1/auth/email-verification/resend").contentType(MediaType.APPLICATION_JSON)
                .content("{}")).andExpect(status().isBadRequest());
    }

    @Test
    void refresh_rotates_and_logout_ends_the_session() throws Exception {
        JsonNode first = signedIn("ana@example.com");
        String refresh = first.get("refreshToken").asText();

        String body = http.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        http.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refresh + "\"}")).andExpect(status().isUnauthorized());

        JsonNode second = json.readTree(body);
        http.perform(post("/api/v1/auth/logout").header("Authorization", "Bearer " + second.get("accessToken").asText())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + second.get("refreshToken").asText() + "\"}"))
                .andExpect(status().isNoContent());
        http.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + second.get("refreshToken").asText() + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void the_profile_edits_name_and_phone_and_changes_the_password() throws Exception {
        JsonNode session = signedIn("luis@example.com");
        String bearer = "Bearer " + session.get("accessToken").asText();

        http.perform(get("/api/v1/auth/me").header("Authorization", bearer))
                .andExpect(status().isOk()).andExpect(jsonPath("$.email").value("luis@example.com"));
        http.perform(patch("/api/v1/auth/me").header("Authorization", bearer).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fullName\":\"Luis Rojas\",\"phone\":null}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fullName").value("Luis Rojas"))
                .andExpect(jsonPath("$.phone").isEmpty());
        http.perform(patch("/api/v1/auth/me").header("Authorization", bearer).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"x@example.com\"}")).andExpect(status().isBadRequest());

        http.perform(post("/api/v1/auth/me/password").header("Authorization", bearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"WrongPass123\",\"newPassword\":\"NewPass2026\"}"))
                .andExpect(status().isUnprocessableEntity());
        http.perform(post("/api/v1/auth/me/password").header("Authorization", bearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"SecurePass123\",\"newPassword\":\"NewPass2026\"}"))
                .andExpect(status().isNoContent());
        http.perform(login("luis@example.com", "NewPass2026")).andExpect(status().isOk());
        http.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
    }

    private JsonNode signedIn(String email) throws Exception {
        register(email);
        return Verification.confirm(http, json, email);
    }

    private String code(String email) throws Exception {
        return Verification.code(http, json, email);
    }

    private void register(String email) throws Exception {
        http.perform(post("/api/v1/auth/register").header("Idempotency-Key", "register-" + email)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fullName\":\"Cliente Nuevo\",\"email\":\"" + email
                                + "\",\"password\":\"SecurePass123\",\"phone\":\"+573001112233\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.emailVerified").value(false))
                .andExpect(jsonPath("$.accessToken").doesNotExist());
    }

    private static org.springframework.test.web.servlet.RequestBuilder login(String email, String password) {
        return post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, password));
    }

    private static org.springframework.test.web.servlet.RequestBuilder confirm(String email, String code) {
        return post("/api/v1/auth/email-verification/confirm").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"%s\",\"code\":\"%s\"}".formatted(email, code));
    }

    private static org.springframework.test.web.servlet.RequestBuilder resend(String email) {
        return post("/api/v1/auth/email-verification/resend").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\"}");
    }
}
