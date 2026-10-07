package co.edu.corhuila.barbersaas.identityauth.application.usecase;

import co.edu.corhuila.barbersaas.identityauth.application.port.in.OutboxRelayUseCases;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxEvent;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxStore;
import java.time.Clock;
import java.util.List;
import java.util.UUID;

/**
 * Hands the outbox to barber-saas-worker and records what it could deliver (ADR-016, DEC-AUTH-08).
 * A published row loses its reset code: the secret was needed only until the e-mail was handed over.
 */
public class RelayOutbox implements OutboxRelayUseCases {

    /** Every identity-auth event is at version 1; it grows only when a payload gains a field. */
    static final int VERSION = 1;
    static final List<String> SECRETS = List.of("code");

    private final OutboxStore outbox;
    private final Clock clock;

    public RelayOutbox(OutboxStore outbox, Clock clock) {
        this.outbox = outbox;
        this.clock = clock;
    }

    @Override
    public List<EventEnvelope> pending(int limit) {
        return outbox.pending(limit).stream().map(RelayOutbox::envelope).toList();
    }

    @Override
    public void published(UUID eventId) {
        if (!outbox.markPublished(eventId, clock.instant(), SECRETS)) {
            throw new OutboxEventNotFound();
        }
    }

    @Override
    public void failed(UUID eventId, String reason) {
        if (!outbox.markFailed(eventId, reason, clock.instant())) {
            throw new OutboxEventNotFound();
        }
    }

    /** A user's event has no tenant unless its payload names one (a client's reset does not). */
    private static EventEnvelope envelope(OutboxStore.Stored s) {
        OutboxEvent e = s.event();
        Object shop = e.payload().get("barbershopId");
        return new EventEnvelope(e.id(), e.type(), VERSION, e.occurredAt(), OutboxEvent.AGGREGATE_TYPE, e.aggregateId(),
                shop == null ? null : UUID.fromString(shop.toString()), s.correlationId(), e.payload());
    }
}
