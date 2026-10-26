package co.edu.corhuila.barbersaas.identityauth.adapter.out.security;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.RefreshTokens;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Opaque refresh tokens, valid 7 days and single use (HU-AUTH-005). The client receives the random
 * value once; the database keeps only its SHA-256, so a leaked table cannot be replayed. Without a
 * database (development without DATABASE_URL) the hashes live in memory.
 */
public class OpaqueRefreshTokens implements RefreshTokens {

    static final Duration LIFETIME = Duration.ofDays(7);

    private record Live(UUID userId, Instant expiresAt) { }

    private final SecureRandom random = new SecureRandom();
    private final JdbcTemplate jdbc;
    private final Map<String, Live> memory = new ConcurrentHashMap<>();

    public OpaqueRefreshTokens(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public String issueFor(UUID userId, Instant now) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        if (jdbc != null) {
            jdbc.update("INSERT INTO identity_auth.refresh_token (id, user_id, token_hash, expires_at, created_at) "
                            + "VALUES (?, ?, ?, ?, ?)",
                    UUID.randomUUID(), userId, sha256(token), Timestamp.from(now.plus(LIFETIME)), Timestamp.from(now));
        } else {
            memory.put(sha256(token), new Live(userId, now.plus(LIFETIME)));
        }
        return token;
    }

    /** One UPDATE ... RETURNING: two requests with the same token cannot both get it. */
    @Override
    public Optional<UUID> use(String token, Instant now) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        if (jdbc == null) {
            Live live = memory.remove(sha256(token));
            return live == null || !live.expiresAt().isAfter(now) ? Optional.empty() : Optional.of(live.userId());
        }
        Timestamp at = Timestamp.from(now);
        List<UUID> users = jdbc.query("UPDATE identity_auth.refresh_token SET revoked_at = ? "
                        + "WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ? RETURNING user_id",
                (rs, n) -> rs.getObject("user_id", UUID.class), at, sha256(token), at);
        return users.stream().findFirst();
    }

    @Override
    public void revoke(UUID userId, String token, Instant now) {
        if (token == null) {
            return;
        }
        if (jdbc == null) {
            memory.computeIfPresent(sha256(token), (hash, live) -> live.userId().equals(userId) ? null : live);
            return;
        }
        jdbc.update("UPDATE identity_auth.refresh_token SET revoked_at = ? "
                + "WHERE token_hash = ? AND user_id = ? AND revoked_at IS NULL", Timestamp.from(now), sha256(token), userId);
    }

    @Override
    public void revokeAll(UUID userId, String keep, Instant now) {
        String kept = keep == null ? "" : sha256(keep);
        if (jdbc == null) {
            memory.entrySet().removeIf(e -> e.getValue().userId().equals(userId) && !e.getKey().equals(kept));
            return;
        }
        jdbc.update("UPDATE identity_auth.refresh_token SET revoked_at = ? "
                + "WHERE user_id = ? AND revoked_at IS NULL AND token_hash <> ?", Timestamp.from(now), userId, kept);
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
