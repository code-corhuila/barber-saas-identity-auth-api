package co.edu.corhuila.barbersaas.identityauth.adapter.out.persistence;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxEvent;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxStore;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordResets;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Used when DATABASE_URL is empty, next to InMemoryUserRepository; there are no refresh tokens to revoke. */
public class InMemoryPasswordResets implements PasswordResets, OutboxStore {

    private record Row(OutboxEvent event, Instant publishedAt, Instant failedAt, String lastError) { }

    private final InMemoryUserRepository users;
    private final List<ResetCode> codes = new ArrayList<>();
    private final Map<UUID, Instant> usedAt = new LinkedHashMap<>();
    private final Map<UUID, Row> outbox = new LinkedHashMap<>();

    public InMemoryPasswordResets(InMemoryUserRepository users) {
        this.users = users;
    }

    @Override
    public synchronized void saveRequest(ResetCode code, OutboxEvent event) {
        codes.stream().filter(c -> c.userId().equals(code.userId())).forEach(c -> usedAt.putIfAbsent(c.id(),
                code.createdAt()));
        codes.add(code);
        outbox.put(event.id(), new Row(event, null, null, null));
    }

    @Override
    public synchronized List<ResetCode> usable(UUID userId, Instant now) {
        return codes.stream()
                .filter(c -> c.userId().equals(userId) && !usedAt.containsKey(c.id()) && c.expiresAt().isAfter(now))
                .sorted(Comparator.comparing(ResetCode::createdAt).reversed()).toList();
    }

    @Override
    public synchronized boolean consume(UUID codeId, User user, Instant now) {
        boolean usable = codes.stream().anyMatch(c -> c.id().equals(codeId) && c.userId().equals(user.id())
                && c.expiresAt().isAfter(now));
        if (!usable || usedAt.putIfAbsent(codeId, now) != null) {
            return false;
        }
        users.replace(user);
        return true;
    }

    @Override
    public synchronized List<Stored> pending(int limit) {
        return outbox.values().stream().filter(r -> r.publishedAt() == null && r.failedAt() == null)
                .sorted(Comparator.comparing(r -> r.event().occurredAt()))
                .limit(limit).map(r -> new Stored(r.event(), "none")).toList();
    }

    @Override
    public synchronized boolean markPublished(UUID id, Instant now, List<String> secrets) {
        Row row = outbox.get(id);
        if (row == null) {
            return false;
        }
        Map<String, Object> payload = new LinkedHashMap<>(row.event().payload());
        secrets.forEach(payload::remove);
        OutboxEvent e = row.event();
        outbox.put(id, new Row(new OutboxEvent(e.id(), e.aggregateId(), e.type(), payload, e.occurredAt()),
                row.publishedAt() == null ? now : row.publishedAt(), row.failedAt(), row.lastError()));
        return true;
    }

    @Override
    public synchronized boolean markFailed(UUID id, String reason, Instant now) {
        Row row = outbox.get(id);
        if (row == null) {
            return false;
        }
        outbox.put(id, new Row(row.event(), row.publishedAt(), row.failedAt() == null ? now : row.failedAt(), reason));
        return true;
    }
}
