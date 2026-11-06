package co.edu.corhuila.barbersaas.identityauth.app;

import static org.hamcrest.Matchers.is;
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
import org.springframework.test.web.servlet.ResultActions;

/** DEC-AUTH-11: the public sign-up tells a taken e-mail apart, so nobody waits for a code. */
@SpringBootTest
@AutoConfigureMockMvc
class RegisterTakenEmailTest {

    @Autowired
    private MockMvc http;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
    }

    @Test
    void aTakenEmailIs422() throws Exception {
        register("taken.first@example.com", "taken-0001").andExpect(status().isCreated());

        register("Taken.First@example.com", "taken-0002")
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error", is("BUSINESS_RULE_VIOLATION")))
                .andExpect(jsonPath("$.message", is("The email is already registered")));
    }

    @Test
    void aRetryWithTheSameKeyIsStillNotAnError() throws Exception {
        register("taken.retry@example.com", "taken-0003").andExpect(status().isCreated());

        register("taken.retry@example.com", "taken-0003").andExpect(status().isOk());
    }

    private ResultActions register(String email, String key) throws Exception {
        return http.perform(post("/api/v1/auth/register").header("Idempotency-Key", key)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"fullName\":\"Taken Test\",\"email\":\"" + email
                        + "\",\"password\":\"SecurePass123\",\"phone\":null}"));
    }
}
