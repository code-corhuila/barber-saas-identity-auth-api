package co.edu.corhuila.barbersaas.identityauth.application.usecase;

import co.edu.corhuila.barbersaas.identityauth.application.port.in.PasswordResetUseCases;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.IdGenerator;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxEvent;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordHasher;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordResets;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordResets.ResetCode;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.ResetCodes;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository;
import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;
import co.edu.corhuila.barbersaas.identityauth.domain.model.PasswordPolicy;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * HU-AUTH-002. The code lives 15 minutes, is used once and is stored only as a hash; the e-mail that
 * carries it leaves through the outbox (DEC-AUTH-08), so the code and its event commit together.
 */
public class PasswordResetService implements PasswordResetUseCases {

    static final Duration LIFETIME = Duration.ofMinutes(15);
    static final String EVENT = "PasswordResetRequested";
    /** SEC-03: wrong attempts a code survives, and how often a new code can be asked for. */
    static final int ATTEMPTS = 5;
    static final Duration REQUEST_GAP = Duration.ofMinutes(1);
    static final int REQUESTS_PER_HOUR = 5;

    private final UserRepository users;
    private final PasswordResets resets;
    private final PasswordHasher hasher;
    private final ResetCodes codes;
    private final IdGenerator ids;
    private final Clock clock;

    public PasswordResetService(UserRepository users, PasswordResets resets, PasswordHasher hasher, ResetCodes codes,
                                IdGenerator ids, Clock clock) {
        this.users = users;
        this.resets = resets;
        this.hasher = hasher;
        this.codes = codes;
        this.ids = ids;
        this.clock = clock;
    }

    @Override
    public void request(String email) {
        String code = codes.next();
        // Hashed before the lookup: an unknown e-mail costs the same time as a known one (DEC-AUTH-03).
        String codeHash = hasher.hash(code);
        Optional<User> found = normalized(email).flatMap(users::findByEmail).filter(User::active);
        if (found.isEmpty()) {
            return;
        }
        User user = found.get();
        Instant now = clock.instant();
        if (resets.requestsSince(user.id(), now.minus(REQUEST_GAP)) > 0
                || resets.requestsSince(user.id(), now.minus(Duration.ofHours(1))) >= REQUESTS_PER_HOUR) {
            return;                                  // 202 either way: says nothing about the account
        }
        Instant expiresAt = now.plus(LIFETIME);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("userId", user.id().toString());
        payload.put("email", user.email());
        payload.put("fullName", user.fullName());
        payload.put("code", code);
        payload.put("expiresAt", expiresAt.toString());
        resets.saveRequest(new ResetCode(ids.next(), user.id(), codeHash, expiresAt, now),
                new OutboxEvent(ids.next(), user.id(), EVENT, payload, now));
    }

    @Override
    public void confirm(String email, String code, String newPassword) {
        PasswordPolicy.check(newPassword);
        Instant now = clock.instant();
        User user = normalized(email).flatMap(users::findByEmail).filter(User::active).orElseThrow(this::invalid);
        Optional<ResetCode> found = resets.usable(user.id(), now).stream()
                .filter(c -> code != null && hasher.matches(code, c.codeHash()))
                .findFirst();
        if (found.isEmpty()) {
            resets.recordFailure(user.id(), now, ATTEMPTS);
            throw invalid();
        }
        ResetCode match = found.get();
        // The code reached the inbox, so the address is proven too (ADR-018).
        User updated = user.withPasswordHash(hasher.hash(newPassword));
        if (!updated.emailVerified()) {
            updated = updated.verifiedAt(now);
        }
        if (!resets.consume(match.id(), updated, now)) {
            throw invalid();
        }
    }

    private static Optional<String> normalized(String email) {
        try {
            return Optional.of(User.normalizeEmail(email));
        } catch (BusinessRuleViolation e) {
            return Optional.empty();
        }
    }

    /** One message for an unknown e-mail, a wrong code, an expired one and a used one. */
    private BusinessRuleViolation invalid() {
        return new BusinessRuleViolation("The code is invalid or has expired");
    }
}
