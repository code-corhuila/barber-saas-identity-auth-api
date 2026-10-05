package co.edu.corhuila.barbersaas.identityauth.adapter.out.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.Barbershops.Unavailable;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** HttpBarbershops against a local server standing in for barbershop-api. */
class HttpBarbershopsTest {

    private HttpServer server;
    private final AtomicInteger status = new AtomicInteger(200);
    private final AtomicReference<String> path = new AtomicReference<>();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            path.set(exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath());
            exchange.sendResponseHeaders(status.get(), -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private HttpBarbershops barbershops() {
        return new HttpBarbershops("http://127.0.0.1:" + server.getAddress().getPort() + "/");
    }

    @Test
    void an_open_barbershop_is_read_with_the_discovery_route() {
        UUID id = UUID.randomUUID();

        assertTrue(barbershops().isOpen(id));
        assertEquals("GET /api/v1/barbershops/" + id, path.get());
    }

    @Test
    void a_404_means_closed_or_unknown() {
        status.set(404);

        assertFalse(barbershops().isOpen(UUID.randomUUID()));
    }

    @Test
    void any_other_answer_or_no_answer_is_unavailable() {
        status.set(500);
        assertThrows(Unavailable.class, () -> barbershops().isOpen(UUID.randomUUID()));

        HttpBarbershops nobody = new HttpBarbershops("http://127.0.0.1:1");
        assertThrows(Unavailable.class, () -> nobody.isOpen(UUID.randomUUID()));
        assertThrows(Unavailable.class, () -> new HttpBarbershops("").isOpen(UUID.randomUUID()));
    }
}
