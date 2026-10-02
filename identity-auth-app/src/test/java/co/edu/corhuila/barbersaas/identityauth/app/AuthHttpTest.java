package co.edu.corhuila.barbersaas.identityauth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** The HTTP contract of auth-service.yaml, with the in-memory repository (no DATABASE_URL). */
@SpringBootTest
@AutoConfigureMockMvc
class AuthHttpTest {

    private static final String BODY = """
            {"fullName":"Maria Garcia","email":"maria@example.com","password":"SecurePass123","phone":"+573001234567"}
            """;

    @Autowired
    private MockMvc http;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        registry.add("JWT_PRIVATE_KEY", () -> pem);
        registry.add("BCRYPT_STRENGTH", () -> "4");
    }

    @Test
    void register_then_retry_then_login() throws Exception {
        http.perform(post("/api/v1/auth/register").header("Idempotency-Key", "register-0001")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(header().exists("X-Correlation-Id"))
                .andExpect(jsonPath("$.user.role").value("CLIENT"))
                .andExpect(jsonPath("$.user.barbershopId").isEmpty())
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist())
                .andExpect(jsonPath("$.expiresIn").value(86400));

        http.perform(post("/api/v1/auth/register").header("Idempotency-Key", "register-0001")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk());

        http.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"MARIA@example.com\",\"password\":\"SecurePass123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    @Test
    void register_without_idempotency_key_is_a_validation_error() throws Exception {
        http.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.traceId").isNotEmpty());
    }

    @Test
    void a_wrong_password_is_401_with_the_envelope() throws Exception {
        http.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nobody@example.com\",\"password\":\"WrongPass123\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value("Incorrect email or password"));
    }

    @Test
    void jwks_and_health_need_no_token() throws Exception {
        http.perform(get("/api/v1/auth/jwks")).andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"));
        http.perform(get("/health")).andExpect(status().isOk());
    }

    @Test
    void an_unknown_route_answers_with_the_envelope() throws Exception {
        http.perform(get("/api/v1/auth/nothing")).andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("NOT_FOUND"));
    }
}
