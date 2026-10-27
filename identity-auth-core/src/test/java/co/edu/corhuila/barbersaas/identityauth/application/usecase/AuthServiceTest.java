package co.edu.corhuila.barbersaas.identityauth.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.AuthResult;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.BarbershopNotFound;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.BarbershopToken;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.CreateBarberCommand;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.CreateOwnerCommand;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.Created;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.EmailNotVerified;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.IdempotencyKeyReused;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.InvalidCredentials;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.RegisterCommand;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.UserNotFound;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.Barbershops;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.EmailVerifications;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxEvent;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.RefreshTokens;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordHasher;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.TokenIssuer;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository;
import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;
import co.edu.corhuila.barbersaas.identityauth.domain.model.Role;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthServiceTest {

    private FakeUsers users;
    private FakeBarbershops barbershops;
    private FakeVerifications verifications;
    private FakeRefreshTokens refreshTokens;
    private Instant now;
    private AuthService service;

    @BeforeEach
    void setUp() {
        users = new FakeUsers();
        barbershops = new FakeBarbershops();
        PasswordHasher hasher = new PasswordHasher() {
            public String hash(String raw) { return "hashed:" + raw; }
            public boolean matches(String raw, String hash) { return hash.equals("hashed:" + raw); }
        };
        TokenIssuer tokens = new TokenIssuer() {
            public IssuedToken issue(User user, Instant now) {
                return new IssuedToken("access-" + user.id(), 86_400);
            }

            public IssuedToken issueBound(User client, UUID barbershopId, Instant now, Duration lifetime) {
                return new IssuedToken("bound-" + client.id() + "-" + barbershopId, lifetime.toSeconds());
            }
        };
        verifications = new FakeVerifications(users);
        refreshTokens = new FakeRefreshTokens();
        now = Instant.parse("2026-10-02T12:00:00Z");
        service = service();
    }

    /** The service with the clock at {@code now}: tests move the clock and build it again. */
    private AuthService service() {
        return new AuthService(users, new PasswordHasher() {
            public String hash(String raw) { return "hashed:" + raw; }
            public boolean matches(String raw, String hash) { return hash.equals("hashed:" + raw); }
        }, new TokenIssuer() {
            public IssuedToken issue(User user, Instant at) {
                return new IssuedToken("access-" + user.id(), 86_400);
            }

            public IssuedToken issueBound(User client, UUID barbershopId, Instant at, Duration lifetime) {
                return new IssuedToken("bound-" + client.id() + "-" + barbershopId, lifetime.toSeconds());
            }
        }, refreshTokens, barbershops, UUID::randomUUID, Clock.fixed(now, ZoneOffset.UTC), verifications,
                () -> "123456");
    }

    @Test
    void register_creates_an_unverified_client_and_emails_a_code_without_tokens() {
        Created result = service.register(command("Maria@Example.com"), "key-00000001");

        assertTrue(result.created());
        assertEquals(Role.CLIENT, result.user().role());
        assertNull(result.user().barbershopId());
        assertEquals("maria@example.com", result.user().email());
        assertFalse(result.user().emailVerified());
        assertEquals(1, verifications.events.size());
        assertEquals("EmailVerificationRequested", verifications.events.get(0).type());
        assertEquals("123456", verifications.events.get(0).payload().get("code"));
        assertEquals("hashed:123456", verifications.codes.get(0).codeHash());
    }

    @Test
    void an_unverified_account_cannot_log_in_but_a_wrong_password_still_looks_the_same() {
        service.register(command("maria@example.com"), "key-00000001");

        assertThrows(EmailNotVerified.class, () -> service.login("maria@example.com", "SecurePass123"));
        assertThrows(InvalidCredentials.class, () -> service.login("maria@example.com", "WrongPass123"));
    }

    @Test
    void the_right_code_verifies_and_signs_in_once() {
        service.register(command("maria@example.com"), "key-00000001");

        AuthResult result = service.confirmEmail("MARIA@example.com", "123456");

        assertTrue(result.user().emailVerified());
        assertTrue(result.accessToken().startsWith("access-"));
        assertThrows(BusinessRuleViolation.class, () -> service.confirmEmail("maria@example.com", "123456"));
        assertEquals("maria@example.com", service.login("maria@example.com", "SecurePass123").user().email());
    }

    @Test
    void a_wrong_or_expired_code_is_refused_with_one_message() {
        service.register(command("maria@example.com"), "key-00000001");

        BusinessRuleViolation wrong = assertThrows(BusinessRuleViolation.class,
                () -> service.confirmEmail("maria@example.com", "000000"));
        now = now.plus(Duration.ofMinutes(16));
        BusinessRuleViolation expired = assertThrows(BusinessRuleViolation.class,
                () -> service().confirmEmail("maria@example.com", "123456"));
        assertEquals(wrong.getMessage(), expired.getMessage());
    }

    @Test
    void five_wrong_codes_retire_the_code_even_for_the_right_one() {
        service.register(command("maria@example.com"), "key-00000001");
        for (int i = 0; i < 4; i++) {
            assertThrows(BusinessRuleViolation.class, () -> service.confirmEmail("maria@example.com", "000000"));
        }
        assertEquals(1, verifications.codes.stream().filter(c -> !verifications.used.contains(c.id())).count());

        assertThrows(BusinessRuleViolation.class, () -> service.confirmEmail("maria@example.com", "000000"));
        assertThrows(BusinessRuleViolation.class, () -> service.confirmEmail("maria@example.com", "123456"));
        assertThrows(EmailNotVerified.class, () -> service.login("maria@example.com", "SecurePass123"));
    }

    @Test
    void resend_waits_a_minute_and_stops_after_five_an_hour() {
        service.register(command("maria@example.com"), "key-00000001");

        service.resendVerification("maria@example.com");                 // same minute: nothing
        assertEquals(1, verifications.events.size());
        for (int i = 1; i <= 5; i++) {
            now = now.plus(Duration.ofMinutes(2));
            service().resendVerification("maria@example.com");
        }
        assertEquals(5, verifications.events.size());                   // the fifth resend is over the limit
        service().resendVerification("nobody@example.com");
        assertEquals(5, verifications.events.size());
    }

    @Test
    void refresh_rotates_the_token_and_a_used_one_is_refused() {
        AuthResult signedIn = signedIn("maria@example.com");

        AuthResult refreshed = service.refresh(signedIn.refreshToken());

        assertTrue(refreshed.accessToken().startsWith("access-"));
        assertThrows(InvalidCredentials.class, () -> service.refresh(signedIn.refreshToken()));
    }

    @Test
    void logout_revokes_the_session() {
        AuthResult signedIn = signedIn("maria@example.com");

        service.logout(signedIn.user().id(), signedIn.refreshToken(), false);

        assertThrows(InvalidCredentials.class, () -> service.refresh(signedIn.refreshToken()));
    }

    @Test
    void the_profile_changes_the_name_and_phone_only() {
        UUID id = signedIn("maria@example.com").user().id();

        User updated = service.updateMe(id, "Maria Lopez", null, true);

        assertEquals("Maria Lopez", updated.fullName());
        assertNull(updated.phone());
        assertEquals("maria@example.com", users.byId.get(id).email());
        assertEquals("Maria Lopez", users.byId.get(id).fullName());
    }

    @Test
    void changing_the_password_needs_the_current_one_and_closes_the_other_sessions() {
        AuthResult first = signedIn("maria@example.com");
        AuthResult second = service.login("maria@example.com", "SecurePass123");
        UUID id = first.user().id();

        assertThrows(BusinessRuleViolation.class, () -> service.changePassword(id, "WrongPass123", "NewPass2026", null));
        service.changePassword(id, "SecurePass123", "NewPass2026", second.refreshToken());

        assertThrows(InvalidCredentials.class, () -> service.refresh(first.refreshToken()));
        service.refresh(second.refreshToken());
        assertEquals(id, service.login("maria@example.com", "NewPass2026").user().id());
    }

    private AuthResult signedIn(String email) {
        service.register(command(email), "key-" + email);
        return service.confirmEmail(email, "123456");
    }

    @Test
    void register_stores_only_the_hash_of_the_password() {
        Created result = service.register(command("maria@example.com"), "key-00000001");

        assertEquals("hashed:SecurePass123", users.byId.get(result.user().id()).passwordHash());
    }

    @Test
    void a_retry_with_the_same_key_returns_the_same_account() {
        Created first = service.register(command("maria@example.com"), "key-00000001");
        Created retry = service.register(command("maria@example.com"), "key-00000001");

        assertFalse(retry.created());
        assertEquals(first.user().id(), retry.user().id());
        assertEquals(1, users.byId.size());
        assertEquals(1, verifications.events.size());                   // no second code on a retry
    }

    @Test
    void the_same_key_with_a_different_body_is_refused() {
        service.register(command("maria@example.com"), "key-00000001");

        assertThrows(IdempotencyKeyReused.class,
                () -> service.register(command("other@example.com"), "key-00000001"));
    }

    @Test
    void an_email_already_registered_is_a_business_rule_violation() {
        service.register(command("maria@example.com"), "key-00000001");

        BusinessRuleViolation e = assertThrows(BusinessRuleViolation.class,
                () -> service.register(command("MARIA@example.com"), "key-00000002"));
        assertEquals("The email is already registered", e.getMessage());
    }

    @Test
    void a_weak_password_is_refused() {
        RegisterCommand weak = new RegisterCommand("Maria", "maria@example.com", "password", null);

        assertThrows(BusinessRuleViolation.class, () -> service.register(weak, "key-00000001"));
    }

    @Test
    void login_with_the_right_password_returns_tokens() {
        service.register(command("maria@example.com"), "key-00000001");
        service.confirmEmail("maria@example.com", "123456");

        AuthResult result = service.login("MARIA@example.com", "SecurePass123");

        assertEquals("maria@example.com", result.user().email());
        assertTrue(result.refreshToken().startsWith("refresh-"));
    }

    @Test
    void login_fails_the_same_way_for_a_wrong_password_and_an_unknown_email() {
        service.register(command("maria@example.com"), "key-00000001");

        InvalidCredentials wrongPassword = assertThrows(InvalidCredentials.class,
                () -> service.login("maria@example.com", "WrongPass123"));
        InvalidCredentials unknown = assertThrows(InvalidCredentials.class,
                () -> service.login("nobody@example.com", "SecurePass123"));
        assertEquals(wrongPassword.getMessage(), unknown.getMessage());
    }

    @Test
    void an_inactive_account_cannot_log_in() {
        User inactive = new User(UUID.randomUUID(), null, "Old", "old@example.com", "hashed:SecurePass123",
                null, null, Role.CLIENT, false, Instant.now());
        users.byId.put(inactive.id(), inactive);

        assertThrows(InvalidCredentials.class, () -> service.login("old@example.com", "SecurePass123"));
    }

    @Test
    void create_owner_makes_an_admin_of_the_given_barbershop_without_tokens() {
        UUID barbershop = UUID.randomUUID();

        Created owner = service.createOwner(owner("Andres@Example.com", barbershop), "saga-1:create-owner");

        assertTrue(owner.created());
        assertEquals(Role.ADMIN_BARBERSHOP, owner.user().role());
        assertEquals(barbershop, owner.user().barbershopId());
        assertEquals("andres@example.com", owner.user().email());
        assertEquals("hashed:SecurePass123", users.byId.get(owner.user().id()).passwordHash());
    }

    @Test
    void a_retried_saga_step_returns_the_same_owner() {
        UUID barbershop = UUID.randomUUID();
        Created first = service.createOwner(owner("andres@example.com", barbershop), "saga-1:create-owner");
        Created retry = service.createOwner(owner("andres@example.com", barbershop), "saga-1:create-owner");

        assertFalse(retry.created());
        assertEquals(first.user().id(), retry.user().id());
        assertEquals(1, users.byId.size());
    }

    @Test
    void an_owner_with_an_email_already_registered_makes_the_saga_compensate() {
        service.register(command("andres@example.com"), "key-00000001");

        BusinessRuleViolation e = assertThrows(BusinessRuleViolation.class,
                () -> service.createOwner(owner("ANDRES@example.com", UUID.randomUUID()), "saga-1:create-owner"));
        assertEquals("The email is already registered", e.getMessage());
    }

    @Test
    void an_owner_needs_a_barbershop() {
        assertThrows(BusinessRuleViolation.class,
                () -> service.createOwner(owner("andres@example.com", null), "saga-1:create-owner"));
    }

    @Test
    void an_owner_adds_a_barber_to_their_own_barbershop() {
        UUID ownerBarbershop = UUID.randomUUID();

        Created barber = service.createBarber(barber("Juan@Example.com"), ownerBarbershop, "key-barber-01");

        assertTrue(barber.created());
        assertEquals(Role.BARBER, barber.user().role());
        assertEquals(ownerBarbershop, barber.user().barbershopId());
        assertEquals("juan@example.com", barber.user().email());
    }

    @Test
    void the_barber_logs_in_with_the_initial_password() {
        service.createBarber(barber("juan@example.com"), UUID.randomUUID(), "key-barber-01");
        service.confirmEmail("juan@example.com", "123456");               // the code goes to the barber's own e-mail

        AuthResult login = service.login("juan@example.com", "Inicial2026");

        assertEquals(Role.BARBER, login.user().role());
    }

    @Test
    void a_retried_barber_creation_returns_the_same_account() {
        UUID ownerBarbershop = UUID.randomUUID();
        Created first = service.createBarber(barber("juan@example.com"), ownerBarbershop, "key-barber-01");
        Created retry = service.createBarber(barber("juan@example.com"), ownerBarbershop, "key-barber-01");

        assertFalse(retry.created());
        assertEquals(first.user().id(), retry.user().id());
    }

    @Test
    void a_barber_with_an_email_already_registered_is_refused() {
        service.register(command("juan@example.com"), "key-00000001");

        assertThrows(BusinessRuleViolation.class,
                () -> service.createBarber(barber("juan@example.com"), UUID.randomUUID(), "key-barber-01"));
    }

    @Test
    void a_client_gets_a_one_hour_token_bound_to_an_open_barbershop() {
        UUID client = service.register(command("maria@example.com"), "key-00000001").user().id();
        UUID barbershop = barbershops.open();

        BarbershopToken token = service.issueBarbershopToken(client, barbershop);

        assertEquals("bound-" + client + "-" + barbershop, token.accessToken());
        assertEquals(3_600, token.expiresIn());
        assertEquals(barbershop, token.barbershopId());
    }

    @Test
    void a_closed_or_unknown_barbershop_is_not_found() {
        UUID client = service.register(command("maria@example.com"), "key-00000001").user().id();

        assertThrows(BarbershopNotFound.class, () -> service.issueBarbershopToken(client, UUID.randomUUID()));
    }

    @Test
    void an_unanswered_barbershop_check_is_unavailable_not_a_token() {
        UUID client = service.register(command("maria@example.com"), "key-00000001").user().id();
        UUID barbershop = barbershops.open();
        barbershops.down = true;

        assertThrows(Barbershops.Unavailable.class, () -> service.issueBarbershopToken(client, barbershop));
    }

    @Test
    void only_an_active_client_account_gets_a_bound_token() {
        UUID barber = service.createBarber(barber("juan@example.com"), UUID.randomUUID(), "key-barber-01").user().id();
        UUID barbershop = barbershops.open();

        assertThrows(InvalidCredentials.class, () -> service.issueBarbershopToken(barber, barbershop));
        assertThrows(InvalidCredentials.class, () -> service.issueBarbershopToken(UUID.randomUUID(), barbershop));
    }

    @Test
    void another_service_reads_a_user_by_id() {
        UUID barbershop = UUID.randomUUID();
        Created barber = service.createBarber(barber("juan@example.com"), barbershop, "key-barber-01");

        User read = service.findUser(barber.user().id());

        assertEquals(Role.BARBER, read.role());
        assertEquals(barbershop, read.barbershopId());
        assertEquals("Juan Perez", read.fullName());
    }

    @Test
    void an_unknown_user_is_not_found() {
        assertThrows(UserNotFound.class, () -> service.findUser(UUID.randomUUID()));
    }

    private static CreateBarberCommand barber(String email) {
        return new CreateBarberCommand("Juan Perez", email, "Inicial2026", "+573009876543");
    }

    private static CreateOwnerCommand owner(String email, UUID barbershopId) {
        return new CreateOwnerCommand("Andres Rojas", email, "SecurePass123", null, barbershopId);
    }

    private static RegisterCommand command(String email) {
        return new RegisterCommand("Maria Garcia", email, "SecurePass123", "+573001234567");
    }

    private static final class FakeBarbershops implements Barbershops {
        final Set<UUID> open = new HashSet<>();
        boolean down;

        UUID open() {
            UUID id = UUID.randomUUID();
            open.add(id);
            return id;
        }

        public boolean isOpen(UUID barbershopId) {
            if (down) {
                throw new Unavailable("barbershop-api did not answer");
            }
            return open.contains(barbershopId);
        }
    }

    private static final class FakeUsers implements UserRepository {
        final Map<UUID, User> byId = new HashMap<>();
        final Map<String, StoredKey> keys = new HashMap<>();

        public Optional<User> findByEmail(String email) {
            return byId.values().stream().filter(u -> u.email().equals(email)).findFirst();
        }

        public java.util.List<User> findActiveOwners(UUID barbershopId) {
            return java.util.List.of();
        }

        public Optional<User> findById(UUID id) {
            return Optional.ofNullable(byId.get(id));
        }

        public Optional<StoredKey> findKey(String key, String operation) {
            return Optional.ofNullable(keys.get(operation + key));
        }

        public void saveNew(User user, IdempotencyRecord key) {
            byId.put(user.id(), user);
            keys.put(key.operation() + key.key(), new StoredKey(user.id(), key.requestHash()));
        }

        public void update(User user, Instant at) {
            byId.put(user.id(), user);
        }
    }

    private static final class FakeVerifications implements EmailVerifications {
        final List<VerificationCode> codes = new ArrayList<>();
        final List<OutboxEvent> events = new ArrayList<>();
        final Set<UUID> used = new HashSet<>();
        final Map<UUID, Integer> failed = new HashMap<>();
        final FakeUsers users;

        FakeVerifications(FakeUsers users) {
            this.users = users;
        }

        public void saveVerification(VerificationCode code, OutboxEvent event) {
            codes.stream().filter(c -> c.userId().equals(code.userId())).forEach(c -> used.add(c.id()));
            codes.add(code);
            events.add(event);
        }

        public List<VerificationCode> usableVerifications(UUID userId, Instant at) {
            return codes.stream().filter(c -> c.userId().equals(userId) && !used.contains(c.id())
                    && c.expiresAt().isAfter(at)).toList();
        }

        public int verificationsSince(UUID userId, Instant since) {
            return (int) codes.stream().filter(c -> c.userId().equals(userId) && !c.createdAt().isBefore(since)).count();
        }

        public void recordVerificationFailure(UUID userId, Instant at, int maxAttempts) {
            usableVerifications(userId, at).forEach(c -> {
                if (failed.merge(c.id(), 1, Integer::sum) >= maxAttempts) {
                    used.add(c.id());
                }
            });
        }

        public boolean consumeVerification(UUID codeId, UUID userId, Instant at) {
            if (!used.add(codeId)) {
                return false;
            }
            users.byId.computeIfPresent(userId, (id, u) -> u.verifiedAt(at));
            return true;
        }
    }

    private static final class FakeRefreshTokens implements RefreshTokens {
        final Map<String, UUID> live = new HashMap<>();
        int issued;

        public String issueFor(UUID userId, Instant at) {
            String token = "refresh-" + userId + "-" + (++issued);
            live.put(token, userId);
            return token;
        }

        public Optional<UUID> use(String token, Instant at) {
            return Optional.ofNullable(live.remove(token));
        }

        public void revoke(UUID userId, String token, Instant at) {
            live.remove(token, userId);
        }

        public void revokeAll(UUID userId, String keep, Instant at) {
            live.entrySet().removeIf(e -> e.getValue().equals(userId) && !e.getKey().equals(keep));
        }
    }
}
