package co.edu.corhuila.barbersaas.identityauth.adapter.out.persistence;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxEvent;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxStore;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordResets;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * identity_auth.password_reset_token and identity_auth.outbox_event. A code and its event commit in
 * one transaction, and so do a used code, the new password hash and the revoked refresh tokens.
 */
public class JdbcPasswordResets implements PasswordResets, OutboxStore {

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final ObjectMapper json;

    public JdbcPasswordResets(JdbcTemplate jdbc, TransactionTemplate tx, ObjectMapper json) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.json = json;
    }

    @Override
    public void saveRequest(ResetCode code, OutboxEvent event) {
        tx.executeWithoutResult(status -> {
            jdbc.update("UPDATE identity_auth.password_reset_token SET used_at = ? "
                    + "WHERE user_id = ? AND used_at IS NULL", Timestamp.from(code.createdAt()), code.userId());
            jdbc.update("INSERT INTO identity_auth.password_reset_token (id, user_id, code_hash, expires_at, created_at) "
                            + "VALUES (?, ?, ?, ?, ?)", code.id(), code.userId(), code.codeHash(),
                    Timestamp.from(code.expiresAt()), Timestamp.from(code.createdAt()));
            String correlationId = Optional.ofNullable(MDC.get("correlationId")).orElse("none");
            jdbc.update("INSERT INTO identity_auth.outbox_event (id, aggregate_type, aggregate_id, event_type, payload, "
                            + "correlation_id, occurred_at) VALUES (?, ?, ?, ?, ?::jsonb, ?, ?)",
                    event.id(), OutboxEvent.AGGREGATE_TYPE, event.aggregateId(), event.type(), toJson(event.payload()),
                    correlationId, Timestamp.from(event.occurredAt()));
        });
    }

    @Override
    public List<ResetCode> usable(UUID userId, Instant now) {
        return jdbc.query("SELECT id, user_id, code_hash, expires_at, created_at FROM identity_auth.password_reset_token "
                        + "WHERE user_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at DESC",
                (rs, n) -> new ResetCode(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class),
                        rs.getString("code_hash"), rs.getTimestamp("expires_at").toInstant(),
                        rs.getTimestamp("created_at").toInstant()),
                userId, Timestamp.from(now));
    }

    @Override
    public boolean consume(UUID codeId, User user, Instant now) {
        Boolean consumed = tx.execute(status -> {
            Timestamp at = Timestamp.from(now);
            int used = jdbc.update("UPDATE identity_auth.password_reset_token SET used_at = ? "
                    + "WHERE id = ? AND user_id = ? AND used_at IS NULL AND expires_at > ?", at, codeId, user.id(), at);
            if (used == 0) {
                return false;
            }
            jdbc.update("UPDATE identity_auth.app_user SET password_hash = ?, updated_at = ? WHERE id = ?",
                    user.passwordHash(), at, user.id());
            jdbc.update("UPDATE identity_auth.refresh_token SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                    at, user.id());
            return true;
        });
        return Boolean.TRUE.equals(consumed);
    }

    /** idx_outbox_event_unpublished serves this read: pending only, oldest first. */
    @Override
    public List<Stored> pending(int limit) {
        return jdbc.query("SELECT id, aggregate_id, event_type, payload::text AS payload, correlation_id, occurred_at "
                        + "FROM identity_auth.outbox_event WHERE published_at IS NULL AND failed_at IS NULL "
                        + "ORDER BY occurred_at, id LIMIT ?",
                (rs, n) -> new Stored(new OutboxEvent(rs.getObject("id", UUID.class),
                        rs.getObject("aggregate_id", UUID.class), rs.getString("event_type"),
                        fromJson(rs.getString("payload")), rs.getTimestamp("occurred_at").toInstant()),
                        rs.getString("correlation_id")), limit);
    }

    /** The first confirmation sets published_at; every one strips the secrets again, which changes nothing. */
    @Override
    public boolean markPublished(UUID id, Instant now, List<String> secrets) {
        StringBuilder sql = new StringBuilder("UPDATE identity_auth.outbox_event "
                + "SET published_at = COALESCE(published_at, ?), payload = payload");
        List<Object> args = new ArrayList<>();
        args.add(Timestamp.from(now));
        for (String secret : secrets) {
            sql.append(" - ?");
            args.add(secret);
        }
        sql.append(" WHERE id = ?");
        args.add(id);
        return jdbc.update(sql.toString(), args.toArray()) == 1;
    }

    @Override
    public boolean markFailed(UUID id, String reason, Instant now) {
        return jdbc.update("UPDATE identity_auth.outbox_event SET failed_at = COALESCE(failed_at, ?), last_error = ? "
                + "WHERE id = ?", Timestamp.from(now), reason, id) == 1;
    }

    private String toJson(Map<String, Object> payload) {
        try {
            return json.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private Map<String, Object> fromJson(String payload) {
        try {
            return json.readValue(payload, new TypeReference<>() { });
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
