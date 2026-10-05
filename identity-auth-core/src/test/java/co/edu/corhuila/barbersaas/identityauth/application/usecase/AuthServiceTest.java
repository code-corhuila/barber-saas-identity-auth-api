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
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.IdempotencyKeyReused;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.InvalidCredentials;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.RegisterCommand;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.UserNotFound;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.Barbershops;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthServiceTest {

    private FakeUsers users;
    private FakeBarbershops barbershops;
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
        service = new AuthService(users, hasher, tokens, (userId, now) -> "refresh-" + userId, barbershops,
                UUID::randomUUID, Clock.fixed(Instant.parse("2026-10-02T12:00:00Z"), ZoneOffset.UTC));
    }

    @Test
    void register_creates_a_client_without_barbershop_and_logs_it_in() {
        AuthResult result = service.register(command("Maria@Example.com"), "key-00000001");

        assertTrue(result.created());
        assertEquals(Role.CLIENT, result.user().role());
        assertNull(result.user().barbershopId());
        assertEquals("maria@example.com", result.user().email());
        assertEquals(86_400, result.expiresIn());
        assertTrue(result.accessToken().startsWith("access-"));
    }

    @Test
    void register_stores_only_the_hash_of_the_password() {
        AuthResult result = service.register(command("maria@example.com"), "key-00000001");

        assertEquals("hashed:SecurePass123", users.byId.get(result.user().id()).passwordHash());
    }

    @Test
    void a_retry_with_the_same_key_returns_the_same_account() {
        AuthResult first = service.register(command("maria@example.com"), "key-00000001");
        AuthResult retry = service.register(command("maria@example.com"), "key-00000001");

        assertFalse(retry.created());
        assertEquals(first.user().id(), retry.user().id());
        assertEquals(1, users.byId.size());
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
    }
}
