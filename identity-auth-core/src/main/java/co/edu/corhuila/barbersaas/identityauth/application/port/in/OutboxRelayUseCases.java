package co.edu.corhuila.barbersaas.identityauth.application.port.in;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** The outbox relay of DEC-AUTH-08 (ADR-016); the HTTP adapter admits only barber-saas-worker. */
public interface OutboxRelayUseCases {

    /** EventEnvelope of _shared.yaml: what every consumer receives on POST /internal/v1/events. */
    record EventEnvelope(UUID id, String type, int version, Instant occurredAt, String aggregateType,
                         UUID aggregateId, UUID barbershopId, String correlationId, Map<String, Object> payload) { }

    /** The oldest pending events, already as envelopes. */
    List<EventEnvelope> pending(int limit);

    /** OutboxEventNotFound for an unknown id; confirming again is accepted and changes nothing. */
    void published(UUID eventId);

    /** After a consumer answered 4xx or after 8 attempts; the event leaves the pending list. */
    void failed(UUID eventId, String reason);

    /** No outbox row with that id: 404. */
    class OutboxEventNotFound extends RuntimeException {
        public OutboxEventNotFound() {
            super("The outbox event does not exist");
        }
    }
}
