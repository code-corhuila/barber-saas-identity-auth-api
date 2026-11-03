package co.edu.corhuila.barbersaas.identityauth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** docs#155: ten failed sign-ins of one e-mail answer 429 with the envelope; another e-mail is not touched. */
@SpringBootTest
@AutoConfigureMockMvc
class SignInLockHttpTest {

    @Autowired
    private MockMvc http;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
    }

    @Test
    void the_eleventh_attempt_is_429_and_another_email_still_gets_401() throws Exception {
        for (int i = 0; i < 10; i++) {
            http.perform(login("locked.flood@example.com")).andExpect(status().isUnauthorized());
        }

        http.perform(login("locked.flood@example.com"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("TOO_MANY_REQUESTS"))
                .andExpect(jsonPath("$.traceId").isNotEmpty());
        http.perform(login("not.locked@example.com")).andExpect(status().isUnauthorized());
    }

    private static org.springframework.test.web.servlet.RequestBuilder login(String email) {
        return post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"WrongPass123\"}");
    }
}
