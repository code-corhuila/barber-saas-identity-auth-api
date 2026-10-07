package co.edu.corhuila.barbersaas.identityauth.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxEvent;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordHasher;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordResets;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository;
import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;
import co.edu.corhuila.barbersaas.identityauth.domain.model.Role;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PasswordResetServiceTest {

    private static final Instant T0 = Instant.parse("2026-10-07T12:00:00Z");

    private final MutableClock clock = new MutableClock();
    private final Map<UUID, User> users = new HashMap<>();
    private final FakeResets resets = new FakeResets();
    private final List<String> hashed = new ArrayList<>();
    private final List<String> nextCodes = new ArrayList<>(List.of("123456", "654321", "111111"));
    private PasswordResetService service;
    private User maria;

    @BeforeEach
    void setUp() {
        PasswordHasher hasher = new PasswordHasher() {
            public String hash(String raw) {
                hashed.add(raw);
                return "hashed:" + raw;
            }

            public boolean matches(String raw, String hash) {
                return hash.equals("hashed:" + raw);
            }
        };
        maria = new User(UUID.randomUUID(), null, "Maria Lopez", "maria@example.com", "hashed:OldPass123", null, null,
                Role.CLIENT, true, T0);
        users.put(maria.id(), maria);
        service = new PasswordResetService(new Users(), resets, hasher, () -> nextCodes.remove(0), UUID::randomUUID,
                clock);
    }

    @Test
    void a_request_stores_the_hash_and_writes_the_event_with_the_code() {
        service.request(" Maria@Example.com ");

        PasswordResets.ResetCode stored = resets.codes.get(0);
        assertEquals("hashed:123456", stored.codeHash());
        assertEquals(T0.plusSeconds(900), stored.expiresAt());
        OutboxEvent event = resets.events.get(0);
        assertEquals("PasswordResetRequested", event.type());
        assertEquals(maria.id(), event.aggregateId());
        assertEquals(List.of("userId", "email", "fullName", "code", "expiresAt"),
                List.copyOf(event.payload().keySet()));
        assertEquals("123456", event.payload().get("code"));
        assertEquals("2026-10-07T12:15:00Z", event.payload().get("expiresAt"));
    }

    @Test
    void an_unknown_or_inactive_email_writes_nothing_but_costs_the_same_hash() {
        service.request("nobody@example.com");
        service.request("not an e-mail");
        users.put(maria.id(), new User(maria.id(), null, maria.fullName(), maria.email(), maria.passwordHash(), null,
                null, Role.CLIENT, false, T0));
        service.request("maria@example.com");

        assertTrue(resets.codes.isEmpty() && resets.events.isEmpty());
        assertEquals(3, hashed.size());
    }

    @Test
    void the_right_code_sets_the_password_once() {
        service.request("maria@example.com");

        service.confirm("maria@example.com", "123456", "NewPass123");

        assertEquals("hashed:NewPass123", users.get(maria.id()).passwordHash());
        assertThrows(BusinessRuleViolation.class, () -> service.confirm("maria@example.com", "123456", "Other1234"));
    }

    @Test
    void a_wrong_expired_or_replaced_code_is_rejected_with_one_message() {
        service.request("maria@example.com");
        BusinessRuleViolation wrong = assertThrows(BusinessRuleViolation.class,
                () -> service.confirm("maria@example.com", "000000", "NewPass123"));
        assertEquals("The code is invalid or has expired", wrong.getMessage());

        service.request("maria@example.com");                 // the first code stops working
        assertThrows(BusinessRuleViolation.class, () -> service.confirm("maria@example.com", "123456", "NewPass123"));

        clock.now = T0.plusSeconds(901);
        assertThrows(BusinessRuleViolation.class, () -> service.confirm("maria@example.com", "654321", "NewPass123"));
        assertThrows(BusinessRuleViolation.class, () -> service.confirm("nobody@example.com", "654321", "NewPass123"));
        assertEquals("hashed:OldPass123", users.get(maria.id()).passwordHash());
    }

    @Test
    void the_new_password_follows_the_policy() {
        service.request("maria@example.com");

        assertThrows(BusinessRuleViolation.class, () -> service.confirm("maria@example.com", "123456", "short"));
        assertFalse(resets.used.contains(resets.codes.get(0).id()));
    }

    private final class Users implements UserRepository {
        public Optional<User> findByEmail(String email) {
            return users.values().stream().filter(u -> u.email().equals(email)).findFirst();
        }

        public Optional<User> findById(UUID id) {
            return Optional.ofNullable(users.get(id));
        }

        public Optional<StoredKey> findKey(String key, String operation) {
            return Optional.empty();
        }

        public void saveNew(User user, IdempotencyRecord key) {
            users.put(user.id(), user);
        }
    }

    private final class FakeResets implements PasswordResets {
        final List<ResetCode> codes = new ArrayList<>();
        final List<OutboxEvent> events = new ArrayList<>();
        final Set<UUID> used = new HashSet<>();

        public void saveRequest(ResetCode code, OutboxEvent event) {
            codes.stream().filter(c -> c.userId().equals(code.userId())).forEach(c -> used.add(c.id()));
            codes.add(code);
            events.add(event);
        }

        public List<ResetCode> usable(UUID userId, Instant now) {
            return codes.stream()
                    .filter(c -> c.userId().equals(userId) && !used.contains(c.id()) && c.expiresAt().isAfter(now))
                    .sorted(Comparator.comparing(ResetCode::createdAt).reversed()).toList();
        }

        public boolean consume(UUID codeId, User user, Instant now) {
            if (!used.add(codeId)) {
                return false;
            }
            users.put(user.id(), user);
            return true;
        }
    }

    private static final class MutableClock extends Clock {
        Instant now = T0;

        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        public Clock withZone(ZoneId zone) {
            return this;
        }

        public Instant instant() {
            return now;
        }
    }
}
