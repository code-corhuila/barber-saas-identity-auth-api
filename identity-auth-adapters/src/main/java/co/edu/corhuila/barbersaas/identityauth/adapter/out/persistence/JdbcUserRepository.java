package co.edu.corhuila.barbersaas.identityauth.adapter.out.persistence;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository;
import co.edu.corhuila.barbersaas.identityauth.domain.model.Role;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/** Reads and writes the schema owned by barber-saas-identity-auth-db. It knows SQL; the domain does not. */
public class JdbcUserRepository implements UserRepository {

    private static final String COLUMNS = "id, barbershop_id, full_name, email, password_hash, phone, "
            + "profile_photo_url, role, is_active, created_at";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public JdbcUserRepository(JdbcTemplate jdbc, TransactionTemplate tx) {
        this.jdbc = jdbc;
        this.tx = tx;
    }

    @Override
    public Optional<User> findByEmail(String normalizedEmail) {
        return jdbc.query("SELECT " + COLUMNS + " FROM identity_auth.app_user WHERE lower(email) = ?",
                (rs, n) -> map(rs), normalizedEmail).stream().findFirst();
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM identity_auth.app_user WHERE id = ?",
                (rs, n) -> map(rs), id).stream().findFirst();
    }

    @Override
    public Optional<StoredKey> findKey(String key, String operation) {
        return jdbc.query("SELECT resource_id, request_hash FROM identity_auth.idempotency_key "
                        + "WHERE key = ? AND operation = ?",
                (rs, n) -> new StoredKey(rs.getObject("resource_id", UUID.class), rs.getString("request_hash")),
                key, operation).stream().findFirst();
    }

    @Override
    public void saveNew(User u, IdempotencyRecord key) {
        try {
            tx.executeWithoutResult(status -> {
                jdbc.update("INSERT INTO identity_auth.app_user (id, barbershop_id, full_name, email, password_hash, "
                                + "phone, profile_photo_url, role, is_active, created_at, updated_at) "
                                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        u.id(), u.barbershopId(), u.fullName(), u.email(), u.passwordHash(), u.phone(),
                        u.profilePhotoUrl(), u.role().name(), u.active(),
                        Timestamp.from(u.createdAt()), Timestamp.from(u.createdAt()));
                jdbc.update("INSERT INTO identity_auth.idempotency_key (key, operation, resource_id, request_hash) "
                        + "VALUES (?, ?, ?, ?)", key.key(), key.operation(), u.id(), key.requestHash());
            });
        } catch (DuplicateKeyException e) {
            throw new EmailAlreadyTaken();
        }
    }

    private static User map(ResultSet rs) throws SQLException {
        return new User(rs.getObject("id", UUID.class), rs.getObject("barbershop_id", UUID.class),
                rs.getString("full_name"), rs.getString("email"), rs.getString("password_hash"),
                rs.getString("phone"), rs.getString("profile_photo_url"), Role.valueOf(rs.getString("role")),
                rs.getBoolean("is_active"), rs.getTimestamp("created_at").toInstant());
    }
}
