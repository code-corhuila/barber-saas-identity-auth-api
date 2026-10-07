package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** The relay side of identity_auth.outbox_event (ADR-016, DEC-AUTH-08): what barber-saas-worker reads and confirms. */
public interface OutboxStore {

    /** A pending row with the correlation id of the request that wrote it. */
    record Stored(OutboxEvent event, String correlationId) { }

    /** Rows with published_at and failed_at both null, oldest occurred_at first, at most {@code limit}. */
    List<Stored> pending(int limit);

    /**
     * Sets published_at once and removes the payload fields in {@code secrets} from the row; false
     * when the id is unknown. Confirming again changes nothing.
     */
    boolean markPublished(UUID id, Instant now, List<String> secrets);

    /** Sets failed_at once and keeps the last reason; false when the id is unknown. */
    boolean markFailed(UUID id, String reason, Instant now);
}
