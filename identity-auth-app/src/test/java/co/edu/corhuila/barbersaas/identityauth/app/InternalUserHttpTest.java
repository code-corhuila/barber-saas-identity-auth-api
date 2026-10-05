package co.edu.corhuila.barbersaas.identityauth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

/** GET /internal/v1/users/{id} (auth-service.yaml, DEC-AUTH-07, ADR-014), with real RS256 tokens. */
@SpringBootTest
@AutoConfigureMockMvc
class InternalUserHttpTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
    }

    @Test
    void barbershop_reads_a_barber_without_contact_data() throws Exception {
        UUID barbershop = UUID.randomUUID();
        String barberId = createBarber(barbershop, "juan@example.com");

        http.perform(get("/internal/v1/users/" + barberId).header("Authorization", "Bearer " + barbershopApi()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(barberId))
                .andExpect(jsonPath("$.fullName").value("Juan Perez"))
                .andExpect(jsonPath("$.role").value("BARBER"))
                .andExpect(jsonPath("$.barbershopId").value(barbershop.toString()))
                .andExpect(jsonPath("$.isActive").value(true))
                .andExpect(jsonPath("$.email").doesNotExist())
                .andExpect(jsonPath("$.phone").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void an_unknown_user_is_404() throws Exception {
        http.perform(get("/internal/v1/users/" + UUID.randomUUID()).header("Authorization", "Bearer " + barbershopApi()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("NOT_FOUND"));
    }

    @Test
    void only_barbershop_api_can_read_users() throws Exception {
        String barberId = createBarber(UUID.randomUUID(), "pedro@example.com");
        String workflow = InternalHttpTest.token("barber-saas-workflow", "SERVICE", null);
        String owner = InternalHttpTest.token(UUID.randomUUID().toString(), "ADMIN_BARBERSHOP", UUID.randomUUID());
        String client = InternalHttpTest.token(UUID.randomUUID().toString(), "CLIENT", null);
        String impostor = InternalHttpTest.token("barber-saas-barbershop-api", "CLIENT", null);

        for (String token : new String[] {workflow, owner, client, impostor}) {
            http.perform(get("/internal/v1/users/" + barberId).header("Authorization", "Bearer " + token))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"));
        }
        http.perform(get("/internal/v1/users/" + barberId)).andExpect(status().isUnauthorized());
    }

    @Test
    void an_id_that_is_not_a_uuid_is_400() throws Exception {
        http.perform(get("/internal/v1/users/not-a-uuid").header("Authorization", "Bearer " + barbershopApi()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
    }

    private static String barbershopApi() throws Exception {
        return InternalHttpTest.token("barber-saas-barbershop-api", "SERVICE", null);
    }

    private String createBarber(UUID barbershop, String email) throws Exception {
        String owner = InternalHttpTest.token(UUID.randomUUID().toString(), "ADMIN_BARBERSHOP", barbershop);
        String body = http.perform(post("/api/v1/auth/barbers").header("Authorization", "Bearer " + owner)
                        .header("Idempotency-Key", "barber-" + email).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fullName\":\"Juan Perez\",\"email\":\"" + email + "\",\"password\":\"Inicial2026\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body).get("id").asText();
    }
}
