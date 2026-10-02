package co.edu.corhuila.barbersaas.identityauth.application.usecase;

import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.IdGenerator;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordHasher;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.RefreshTokens;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.TokenIssuer;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository.IdempotencyRecord;
import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;
import co.edu.corhuila.barbersaas.identityauth.domain.model.PasswordPolicy;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;

public class AuthService implements AuthUseCases {

    static final String REGISTER_OPERATION = "POST /api/v1/auth/register";
    private static final char SEPARATOR = 0;

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final TokenIssuer tokens;
    private final RefreshTokens refreshTokens;
    private final IdGenerator ids;
    private final Clock clock;

    public AuthService(UserRepository users, PasswordHasher hasher, TokenIssuer tokens,
                       RefreshTokens refreshTokens, IdGenerator ids, Clock clock) {
        this.users = users;
        this.hasher = hasher;
        this.tokens = tokens;
        this.refreshTokens = refreshTokens;
        this.ids = ids;
        this.clock = clock;
    }

    @Override
    public AuthResult register(RegisterCommand command, String idempotencyKey) {
        String requestHash = sha256(String.join(String.valueOf(SEPARATOR), String.valueOf(command.fullName()),
                String.valueOf(command.email()), String.valueOf(command.password()), String.valueOf(command.phone())));

        // A retry with the same key returns the first account; it never creates a second one.
        Optional<UserRepository.StoredKey> stored = users.findKey(idempotencyKey, REGISTER_OPERATION);
        if (stored.isPresent()) {
            if (!stored.get().requestHash().equals(requestHash)) {
                throw new IdempotencyKeyReused();
            }
            User first = users.findById(stored.get().resourceId()).orElseThrow();
            return authenticate(first, false);
        }

        PasswordPolicy.check(command.password());
        String email = User.normalizeEmail(command.email());
        if (users.findByEmail(email).isPresent()) {
            throw new BusinessRuleViolation("The email is already registered");
        }
        User user = User.newClient(ids.next(), command.fullName(), email, hasher.hash(command.password()),
                command.phone(), clock.instant());
        try {
            users.saveNew(user, new IdempotencyRecord(idempotencyKey, REGISTER_OPERATION, requestHash));
        } catch (UserRepository.EmailAlreadyTaken e) {
            throw new BusinessRuleViolation(e.getMessage());
        }
        return authenticate(user, true);
    }

    @Override
    public AuthResult login(String email, String password) {
        String normalized;
        try {
            normalized = User.normalizeEmail(email);
        } catch (BusinessRuleViolation e) {
            throw new InvalidCredentials();
        }
        User user = users.findByEmail(normalized)
                .filter(User::active)
                .filter(u -> password != null && hasher.matches(password, u.passwordHash()))
                .orElseThrow(InvalidCredentials::new);
        return authenticate(user, false);
    }

    private AuthResult authenticate(User user, boolean created) {
        Instant now = clock.instant();
        TokenIssuer.IssuedToken access = tokens.issue(user, now);
        String refresh = refreshTokens.issueFor(user.id(), now);
        return new AuthResult(access.token(), refresh, access.expiresInSeconds(), user, created);
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
