package co.edu.corhuila.barbersaas.identityauth.domain.model;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UserTest {

    @Test
    void barbershop_staff_needs_a_barbershop() {
        assertThrows(BusinessRuleViolation.class, () -> user(Role.BARBER, null));
        assertDoesNotThrow(() -> user(Role.BARBER, UUID.randomUUID()));
    }

    @Test
    void clients_and_super_admins_have_no_barbershop() {
        assertThrows(BusinessRuleViolation.class, () -> user(Role.CLIENT, UUID.randomUUID()));
        assertThrows(BusinessRuleViolation.class, () -> user(Role.SUPER_ADMIN, UUID.randomUUID()));
    }

    @Test
    void an_invalid_email_is_refused() {
        assertThrows(BusinessRuleViolation.class, () -> User.normalizeEmail("not-an-email"));
    }

    @Test
    void the_full_name_has_at_most_120_characters() {
        String tooLong = "a".repeat(121);
        assertThrows(BusinessRuleViolation.class, () -> new User(UUID.randomUUID(), null, tooLong,
                "a@example.com", "hash", null, null, Role.CLIENT, true, Instant.now()));
    }

    private static User user(Role role, UUID barbershopId) {
        return new User(UUID.randomUUID(), barbershopId, "Name", "a@example.com", "hash", null, null, role, true,
                Instant.now());
    }
}
