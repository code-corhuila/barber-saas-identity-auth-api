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

/** The MVP 3 internal reads (auth-service.yaml 3.0.0, DEC-AUTH-10), with real RS256 tokens. */
@SpringBootTest
@AutoConfigureMockMvc
class InternalContactHttpTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
    }

    @Test
    void platform_admin_reads_the_owners_of_one_barbershop() throws Exception {
        UUID barbershop = UUID.randomUUID();
        String ownerId = createOwner("owner-a@example.com", barbershop);
        createOwner("owner-b@example.com", UUID.randomUUID());

        http.perform(get("/internal/v1/owners").param("barbershopId", barbershop.toString())
                        .header("Authorization", "Bearer " + service("barber-saas-platform-admin-api")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].userId").value(ownerId))
                .andExpect(jsonPath("$.data[0].fullName").value("Andres Rojas"))
                .andExpect(jsonPath("$.data[0].email").value("owner-a@example.com"));
    }

    @Test
    void an_unknown_barbershop_has_no_owners_and_the_id_is_required() throws Exception {
        String platformAdmin = service("barber-saas-platform-admin-api");
        http.perform(get("/internal/v1/owners").param("barbershopId", UUID.randomUUID().toString())
                        .header("Authorization", "Bearer " + platformAdmin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(0));
        http.perform(get("/internal/v1/owners").header("Authorization", "Bearer " + platformAdmin))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
    }

    @Test
    void notifications_reads_a_users_contact() throws Exception {
        String ownerId = createOwner("contact@example.com", UUID.randomUUID());

        http.perform(get("/internal/v1/users/" + ownerId + "/contact")
                        .header("Authorization", "Bearer " + service("barber-saas-notifications-api")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(ownerId))
                .andExpect(jsonPath("$.email").value("contact@example.com"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
        http.perform(get("/internal/v1/users/" + UUID.randomUUID() + "/contact")
                        .header("Authorization", "Bearer " + service("barber-saas-notifications-api")))
                .andExpect(status().isNotFound());
    }

    @Test
    void appointment_reads_a_user_without_contact_data() throws Exception {
        String ownerId = createOwner("reviewer@example.com", UUID.randomUUID());

        http.perform(get("/internal/v1/users/" + ownerId)
                        .header("Authorization", "Bearer " + service("barber-saas-appointment-api")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fullName").value("Andres Rojas"))
                .andExpect(jsonPath("$.email").doesNotExist());
    }

    @Test
    void each_read_accepts_only_its_caller() throws Exception {
        String ownerId = createOwner("guarded@example.com", UUID.randomUUID());
        String barbershopApi = service("barber-saas-barbershop-api");
        String notifications = service("barber-saas-notifications-api");
        String platformAdmin = service("barber-saas-platform-admin-api");
        String user = InternalHttpTest.token(UUID.randomUUID().toString(), "ADMIN_BARBERSHOP", UUID.randomUUID());

        for (String token : new String[] {barbershopApi, platformAdmin, user}) {
            http.perform(get("/internal/v1/users/" + ownerId + "/contact").header("Authorization", "Bearer " + token))
                    .andExpect(status().isForbidden());
        }
        for (String token : new String[] {barbershopApi, notifications, user}) {
            http.perform(get("/internal/v1/owners").param("barbershopId", UUID.randomUUID().toString())
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isForbidden());
        }
        http.perform(get("/internal/v1/users/" + ownerId).header("Authorization", "Bearer " + notifications))
                .andExpect(status().isForbidden());
    }

    private static String service(String name) throws Exception {
        return InternalHttpTest.token(name, "SERVICE", null);
    }

    private String createOwner(String email, UUID barbershopId) throws Exception {
        String body = """
                {"fullName":"Andres Rojas","email":"%s","password":"SecurePass123","barbershopId":"%s"}
                """.formatted(email, barbershopId);
        String answer = http.perform(post("/internal/v1/owners")
                        .header("Authorization", "Bearer " + service("barber-saas-workflow"))
                        .header("Idempotency-Key", "saga-" + email).contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(answer).get("id").asText();
    }
}
