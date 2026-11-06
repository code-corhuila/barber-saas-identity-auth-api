package co.edu.corhuila.barbersaas.identityauth.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** docs#168: one audit line per success, none for a refused request, never a secret. */
@SpringBootTest
@AutoConfigureMockMvc
class AuditLogTest {

    private static final String TRACE = "11111111-2222-3333-4444-555555555555";

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    private final ListAppender<ILoggingEvent> lines = new ListAppender<>();

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
    }

    @BeforeEach
    void capture() {
        lines.start();
        ((Logger) LoggerFactory.getLogger("audit")).addAppender(lines);
    }

    @AfterEach
    void release() {
        ((Logger) LoggerFactory.getLogger("audit")).detachAppender(lines);
    }

    @Test
    void passwordChangeWritesOneAuditLineWithoutThePassword() throws Exception {
        JsonNode session = signedIn("audit.change@example.com");
        lines.list.clear();

        http.perform(changePassword(session, "SecurePass123", "AuditNew2026")
                        .header("X-Correlation-Id", TRACE)
                        .header("X-Forwarded-For", "203.0.113.99, 203.0.113.7"))
                .andExpect(status().isNoContent());

        assertEquals(1, lines.list.size());
        ILoggingEvent line = lines.list.get(0);
        Map<String, Object> fields = fields(line);
        assertEquals("password.changed", line.getFormattedMessage());
        assertEquals(session.get("user").get("id").asText(), String.valueOf(fields.get("user_id")));
        assertEquals(TRACE, fields.get("trace_id"));
        assertEquals("203.0.113.7", fields.get("source_ip"));
        assertFalse(fields.containsKey("barbershopId"));
        String all = line.getFormattedMessage() + fields;
        assertFalse(all.contains("SecurePass123"));
        assertFalse(all.contains("AuditNew2026"));
        assertFalse(all.contains(session.get("accessToken").asText()));
    }

    @Test
    void aRefusedPasswordChangeWritesNothing() throws Exception {
        JsonNode session = signedIn("audit.refused@example.com");
        lines.list.clear();

        http.perform(changePassword(session, "WrongPass123", "AuditNew2026"))
                .andExpect(status().isUnprocessableEntity());
        http.perform(post("/api/v1/auth/me/password").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());

        assertTrue(lines.list.isEmpty());
    }

    @Test
    void aNewBarberWritesOneLineNamingTheBarbershopAndTheOwner() throws Exception {
        UUID barbershop = UUID.randomUUID();
        String ownerId = UUID.randomUUID().toString();
        String owner = InternalHttpTest.token(ownerId, "ADMIN_BARBERSHOP", barbershop);
        lines.list.clear();

        MockHttpServletRequestBuilder create = post("/api/v1/auth/barbers").header("Authorization", "Bearer " + owner)
                .header("Idempotency-Key", "audit-barber-0001").contentType(MediaType.APPLICATION_JSON)
                .content("{\"fullName\":\"Juan Audit\",\"email\":\"audit.barber@example.com\","
                        + "\"password\":\"Inicial2026\",\"phone\":null}");
        http.perform(create).andExpect(status().isCreated());
        http.perform(create).andExpect(status().isOk());      // a retry created nothing: no second line

        assertEquals(1, lines.list.size());
        Map<String, Object> fields = fields(lines.list.get(0));
        assertEquals("barber.created", lines.list.get(0).getFormattedMessage());
        assertEquals(barbershop.toString(), String.valueOf(fields.get("barbershopId")));
        assertEquals(ownerId, fields.get("actor"));
    }

    private static Map<String, Object> fields(ILoggingEvent line) {
        return line.getKeyValuePairs().stream().collect(Collectors.toMap(p -> p.key, p -> p.value));
    }

    private MockHttpServletRequestBuilder changePassword(JsonNode session, String current, String next) {
        return post("/api/v1/auth/me/password").header("Authorization", "Bearer " + session.get("accessToken").asText())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"" + current + "\",\"newPassword\":\"" + next + "\"}");
    }

    private JsonNode signedIn(String email) throws Exception {
        http.perform(post("/api/v1/auth/register").header("Idempotency-Key", "audit-" + email)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fullName\":\"Audit Test\",\"email\":\"" + email
                                + "\",\"password\":\"SecurePass123\",\"phone\":null}"))
                .andExpect(status().isCreated());
        return Verification.confirm(http, json, email);
    }
}
