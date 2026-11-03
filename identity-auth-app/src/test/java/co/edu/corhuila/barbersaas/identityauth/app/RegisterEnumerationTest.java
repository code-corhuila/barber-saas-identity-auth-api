package co.edu.corhuila.barbersaas.identityauth.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Iterator;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** docs#167: the public sign-up answers a taken e-mail exactly like a new one. */
@SpringBootTest
@AutoConfigureMockMvc
class RegisterEnumerationTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @DynamicPropertySource
    static void privateKey(DynamicPropertyRegistry registry) {
        InternalHttpTest.privateKey(registry);
    }

    @Test
    void existingAndNewEmailGetSameResponse() throws Exception {
        register("enum.taken@example.com", "enum-0001");

        MvcResult taken = register("enum.taken@example.com", "enum-0002");
        MvcResult fresh = register("enum.fresh@example.com", "enum-0003");

        assertEquals(fresh.getResponse().getStatus(), taken.getResponse().getStatus());
        JsonNode a = json.readTree(taken.getResponse().getContentAsString());
        JsonNode b = json.readTree(fresh.getResponse().getContentAsString());
        assertEquals(fields(b), fields(a));
        assertEquals(b.get("role"), a.get("role"));
        assertEquals(b.get("emailVerified"), a.get("emailVerified"));
        assertEquals(fresh.getResponse().getHeader("Location") != null, taken.getResponse().getHeader("Location") != null);
    }

    private MvcResult register(String email, String key) throws Exception {
        return http.perform(post("/api/v1/auth/register").header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fullName\":\"Enum Test\",\"email\":\"" + email
                                + "\",\"password\":\"SecurePass123\",\"phone\":null}"))
                .andExpect(status().isCreated())
                .andReturn();
    }

    private static TreeSet<String> fields(JsonNode node) {
        TreeSet<String> names = new TreeSet<>();
        for (Iterator<String> it = node.fieldNames(); it.hasNext(); ) {
            names.add(it.next());
        }
        return names;
    }
}
