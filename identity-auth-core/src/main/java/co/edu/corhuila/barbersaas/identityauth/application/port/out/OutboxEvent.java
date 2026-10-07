package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * A row of identity_auth.outbox_event, written with the change that caused it and relayed later by
 * barber-saas-worker (norm 5.3.11, ADR-016). The adapter adds the correlation id of the request.
 */
public record OutboxEvent(UUID id, UUID aggregateId, String type, Map<String, Object> payload, Instant occurredAt) {

    public static final String AGGREGATE_TYPE = "user";

    public OutboxEvent {
        payload = Collections.unmodifiableMap(new LinkedHashMap<>(payload));
    }
}
