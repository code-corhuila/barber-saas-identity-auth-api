package co.edu.corhuila.barbersaas.identityauth.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.barbersaas.identityauth.application.port.in.OutboxRelayUseCases.EventEnvelope;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.OutboxRelayUseCases.OutboxEventNotFound;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxEvent;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxStore;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class RelayOutboxTest {

    private static final Instant T0 = Instant.parse("2026-10-07T12:00:00Z");

    private final UUID eventId = UUID.randomUUID();
    private final UUID userId = UUID.randomUUID();
    private final Map<UUID, List<String>> published = new HashMap<>();
    private final Map<UUID, String> failed = new HashMap<>();

    private final OutboxStore store = new OutboxStore() {
        public List<Stored> pending(int limit) {
            return List.of(new Stored(new OutboxEvent(eventId, userId, "PasswordResetRequested",
                    Map.of("userId", userId.toString(), "code", "123456"), T0), "corr-1"));
        }

        public boolean markPublished(UUID id, Instant now, List<String> secrets) {
            published.put(id, secrets);
            return id.equals(eventId);
        }

        public boolean markFailed(UUID id, String reason, Instant now) {
            failed.put(id, reason);
            return id.equals(eventId);
        }
    };

    private final RelayOutbox relay = new RelayOutbox(store, Clock.fixed(T0, ZoneOffset.UTC));

    @Test
    void pending_rows_become_envelopes_without_a_tenant() {
        EventEnvelope e = relay.pending(20).get(0);

        assertEquals(eventId, e.id());
        assertEquals(1, e.version());
        assertEquals("user", e.aggregateType());
        assertEquals(userId, e.aggregateId());
        assertNull(e.barbershopId());
        assertEquals("corr-1", e.correlationId());
        assertEquals("123456", e.payload().get("code"));
    }

    @Test
    void publishing_removes_the_code_and_an_unknown_id_is_not_found() {
        relay.published(eventId);
        assertEquals(List.of("code"), published.get(eventId));

        assertThrows(OutboxEventNotFound.class, () -> relay.published(UUID.randomUUID()));
    }

    @Test
    void a_failure_keeps_its_reason() {
        relay.failed(eventId, "notifications 422 UNKNOWN_EVENT_TYPE");
        assertEquals("notifications 422 UNKNOWN_EVENT_TYPE", failed.get(eventId));

        assertThrows(OutboxEventNotFound.class, () -> relay.failed(UUID.randomUUID(), "x"));
    }
}
