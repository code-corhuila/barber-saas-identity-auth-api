package co.edu.corhuila.barbersaas.identityauth.adapter.out.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class InMemorySignInFailuresTest {

    private static final Instant NOW = Instant.parse("2026-11-03T12:00:00Z");

    @Test
    void counts_only_the_failures_inside_the_window_and_clears_on_success() {
        InMemorySignInFailures failures = new InMemorySignInFailures(Duration.ofMinutes(15), 100);
        failures.record("a@example.com", NOW.minus(Duration.ofMinutes(20)));
        failures.record("a@example.com", NOW.minus(Duration.ofMinutes(5)));
        failures.record("a@example.com", NOW);

        assertEquals(2, failures.countSince("a@example.com", NOW.minus(Duration.ofMinutes(15))));
        assertEquals(0, failures.countSince("b@example.com", NOW.minus(Duration.ofMinutes(15))));
        failures.clear("a@example.com");
        assertEquals(0, failures.countSince("a@example.com", NOW.minus(Duration.ofMinutes(15))));
    }

    @Test
    void a_flood_of_new_emails_never_grows_past_the_limit() {
        InMemorySignInFailures failures = new InMemorySignInFailures(Duration.ofMinutes(15), 3);
        for (int i = 0; i < 10; i++) {
            failures.record("flood" + i + "@example.com", NOW);
        }

        assertEquals(1, failures.countSince("flood9@example.com", NOW.minus(Duration.ofMinutes(1))));
        assertEquals(0, failures.countSince("flood0@example.com", NOW.minus(Duration.ofMinutes(1))));
    }
}
