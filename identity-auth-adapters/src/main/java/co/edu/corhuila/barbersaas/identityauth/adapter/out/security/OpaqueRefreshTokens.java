package co.edu.corhuila.barbersaas.identityauth.adapter.out.security;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.RefreshTokens;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Opaque refresh tokens, valid 7 days. The client receives the random value once; the database
 * keeps only its SHA-256, so a leaked table cannot be replayed. Without a database the hash is
 * not stored (development without DATABASE_URL).
 */
public class OpaqueRefreshTokens implements RefreshTokens {

    static final Duration LIFETIME = Duration.ofDays(7);

    private final SecureRandom random = new SecureRandom();
    private final JdbcTemplate jdbc;

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
                    UUID.randomUUID(), userId, sha256(token),
                    java.sql.Timestamp.from(now.plus(LIFETIME)), java.sql.Timestamp.from(now));
        }
        return token;
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
