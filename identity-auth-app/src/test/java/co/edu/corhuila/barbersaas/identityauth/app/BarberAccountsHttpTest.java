package co.edu.corhuila.barbersaas.identityauth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** POST /api/v1/auth/barbers (auth-service.yaml, DEC-AUTH-05, HU-SHOP-002). */
@SpringBootTest
@AutoConfigureMockMvc
class BarberAccountsHttpTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
    }

    @Test
    void an_owner_adds_a_barber_who_then_logs_in_in_the_same_barbershop() throws Exception {
        UUID barbershop = UUID.randomUUID();
        String owner = InternalHttpTest.token(UUID.randomUUID().toString(), "ADMIN_BARBERSHOP", barbershop);

        http.perform(createBarber(owner, "barber-key-0001", barber("juan@example.com")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("BARBER"))
                .andExpect(jsonPath("$.barbershopId").value(barbershop.toString()))
                .andExpect(jsonPath("$.accessToken").doesNotExist());

        http.perform(createBarber(owner, "barber-key-0001", barber("juan@example.com")))
                .andExpect(status().isOk());

        String login = http.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"juan@example.com\",\"password\":\"Inicial2026\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.role").value("BARBER"))
                .andReturn().getResponse().getContentAsString();
        String accessToken = json.readTree(login).get("accessToken").asText();
        String claims = new String(java.util.Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]));
        org.junit.jupiter.api.Assertions.assertTrue(claims.contains(barbershop.toString()));
    }

    @Test
    void the_body_cannot_choose_the_barbershop() throws Exception {
        UUID ownersBarbershop = UUID.randomUUID();
        String owner = InternalHttpTest.token(UUID.randomUUID().toString(), "ADMIN_BARBERSHOP", ownersBarbershop);

        http.perform(createBarber(owner, "barber-key-0002", """
                        {"fullName":"Juan","email":"a@example.com","password":"Inicial2026","barbershopId":"%s"}
                        """.formatted(UUID.randomUUID())))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.barbershopId").value(ownersBarbershop.toString()));
    }

    @Test
    void only_an_owner_can_add_barbers() throws Exception {
        String client = InternalHttpTest.token(UUID.randomUUID().toString(), "CLIENT", null);
        String barber = InternalHttpTest.token(UUID.randomUUID().toString(), "BARBER", UUID.randomUUID());
        String workflow = InternalHttpTest.token("barber-saas-workflow", "SERVICE", null);

        for (String token : new String[] {client, barber, workflow}) {
            http.perform(createBarber(token, "barber-key-0003", barber("b@example.com")))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"));
        }
    }

    @Test
    void without_a_token_it_is_401() throws Exception {
        http.perform(post("/api/v1/auth/barbers").header("Idempotency-Key", "barber-key-0004")
                        .contentType(MediaType.APPLICATION_JSON).content(barber("c@example.com")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void an_email_already_registered_is_422() throws Exception {
        String owner = InternalHttpTest.token(UUID.randomUUID().toString(), "ADMIN_BARBERSHOP", UUID.randomUUID());
        http.perform(createBarber(owner, "barber-key-0005", barber("taken@example.com")))
                .andExpect(status().isCreated());

        http.perform(createBarber(owner, "barber-key-0006", barber("taken@example.com")))
                .andExpect(status().isUnprocessableEntity());
    }

    private static org.springframework.test.web.servlet.RequestBuilder createBarber(String token, String key,
                                                                                     String body) {
        return post("/api/v1/auth/barbers").header("Authorization", "Bearer " + token)
                .header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String barber(String email) {
        return """
                {"fullName":"Juan Perez","email":"%s","password":"Inicial2026","phone":"+573009876543"}
                """.formatted(email);
    }
}
