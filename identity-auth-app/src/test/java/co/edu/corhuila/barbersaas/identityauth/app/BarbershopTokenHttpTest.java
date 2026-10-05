package co.edu.corhuila.barbersaas.identityauth.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;

/** POST /api/v1/auth/barbershop-token (auth-service.yaml, DEC-AUTH-06), barbershop-api stubbed. */
@SpringBootTest
@AutoConfigureMockMvc
class BarbershopTokenHttpTest {

    private static final UUID OPEN = UUID.randomUUID();
    private static final UUID BROKEN = UUID.randomUUID();
    private static final HttpServer BARBERSHOP_API = barbershopApi();

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
        registry.add("BARBERSHOP_API_URL", () -> "http://127.0.0.1:" + BARBERSHOP_API.getAddress().getPort());
    }

    @AfterAll
    static void stop() {
        BARBERSHOP_API.stop(0);
    }

    /** 200 only for OPEN, 500 for BROKEN, 404 for anything else: the discovery read of barbershop-api. */
    private static HttpServer barbershopApi() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/api/v1/barbershops/", exchange -> {
                String path = exchange.getRequestURI().getPath();
                int code = path.endsWith(OPEN.toString()) ? 200 : path.endsWith(BROKEN.toString()) ? 500 : 404;
                exchange.sendResponseHeaders(code, -1);
                exchange.close();
            });
            server.start();
            return server;
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void a_client_gets_a_one_hour_token_bound_to_the_picked_barbershop() throws Exception {
        String login = registerAndLogin("maria@example.com");

        String body = http.perform(barbershopToken(login, OPEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andExpect(jsonPath("$.barbershopId").value(OPEN.toString()))
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        JsonNode claims = claims(json.readTree(body).get("accessToken").asText());
        assertEquals("CLIENT", claims.get("role").asText());
        assertEquals(OPEN.toString(), claims.get("barbershopId").asText());
        assertEquals(claims(login).get("sub").asText(), claims.get("sub").asText());
    }

    @Test
    void a_closed_or_unknown_barbershop_is_not_found() throws Exception {
        http.perform(barbershopToken(registerAndLogin("pedro@example.com"), UUID.randomUUID()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("NOT_FOUND"));
    }

    @Test
    void an_unanswered_check_is_503() throws Exception {
        http.perform(barbershopToken(registerAndLogin("lucia@example.com"), BROKEN))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"));
    }

    @Test
    void only_a_client_can_pick_a_barbershop() throws Exception {
        String owner = InternalHttpTest.token(UUID.randomUUID().toString(), "ADMIN_BARBERSHOP", UUID.randomUUID());
        String barber = InternalHttpTest.token(UUID.randomUUID().toString(), "BARBER", UUID.randomUUID());
        String workflow = InternalHttpTest.token("barber-saas-workflow", "SERVICE", null);

        for (String token : new String[] {owner, barber, workflow}) {
            http.perform(barbershopToken(token, OPEN))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"));
        }
    }

    @Test
    void the_barbershop_is_required_and_a_token_too() throws Exception {
        http.perform(post("/api/v1/auth/barbershop-token")
                        .header("Authorization", "Bearer " + registerAndLogin("ana@example.com"))
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("barbershopId"));

        http.perform(post("/api/v1/auth/barbershop-token").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"barbershopId\":\"" + OPEN + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    private String registerAndLogin(String email) throws Exception {
        String body = http.perform(post("/api/v1/auth/register").header("Idempotency-Key", "reg-" + email)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fullName\":\"Cliente\",\"email\":\"" + email + "\",\"password\":\"Client123\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body).get("accessToken").asText();
    }

    private static RequestBuilder barbershopToken(String token, UUID barbershopId) {
        return post("/api/v1/auth/barbershop-token").header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content("{\"barbershopId\":\"" + barbershopId + "\"}");
    }

    private JsonNode claims(String token) throws Exception {
        return json.readTree(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
    }
}
