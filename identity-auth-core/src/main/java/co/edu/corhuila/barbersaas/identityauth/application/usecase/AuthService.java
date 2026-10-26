package co.edu.corhuila.barbersaas.identityauth.application.usecase;

import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.Barbershops;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.EmailVerifications;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.EmailVerifications.VerificationCode;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.IdGenerator;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.OutboxEvent;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.PasswordHasher;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.RefreshTokens;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.ResetCodes;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.TokenIssuer;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository.IdempotencyRecord;
import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;
import co.edu.corhuila.barbersaas.identityauth.domain.model.PasswordPolicy;
import co.edu.corhuila.barbersaas.identityauth.domain.model.Role;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiFunction;

public class AuthService implements AuthUseCases {

    static final String REGISTER_OPERATION = "POST /api/v1/auth/register";
    static final String CREATE_OWNER_OPERATION = "POST /internal/v1/owners";
    static final String CREATE_BARBER_OPERATION = "POST /api/v1/auth/barbers";
    /** Short because a stateless token cannot be revoked and a barbershop can be suspended (DEC-AUTH-06). */
    static final Duration BARBERSHOP_TOKEN_LIFETIME = Duration.ofHours(1);
    private static final char SEPARATOR = 0;
    /** ADR-018: the code lives 15 minutes; at most one per minute and five per hour per account. */
    static final Duration VERIFICATION_LIFETIME = Duration.ofMinutes(15);
    static final Duration RESEND_GAP = Duration.ofMinutes(1);
    static final int RESENDS_PER_HOUR = 5;
    static final String VERIFICATION_EVENT = "EmailVerificationRequested";

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final TokenIssuer tokens;
    private final RefreshTokens refreshTokens;
    private final Barbershops barbershops;
    private final IdGenerator ids;
    private final Clock clock;
    private final EmailVerifications verifications;
    private final ResetCodes codes;

    public AuthService(UserRepository users, PasswordHasher hasher, TokenIssuer tokens,
                       RefreshTokens refreshTokens, Barbershops barbershops, IdGenerator ids, Clock clock,
                       EmailVerifications verifications, ResetCodes codes) {
        this.users = users;
        this.hasher = hasher;
        this.tokens = tokens;
        this.refreshTokens = refreshTokens;
        this.barbershops = barbershops;
        this.ids = ids;
        this.clock = clock;
        this.verifications = verifications;
        this.codes = codes;
    }

    @Override
    public Created register(RegisterCommand command, String idempotencyKey) {
        return createOnce(idempotencyKey, REGISTER_OPERATION,
                requestHash(command.fullName(), command.email(), command.password(), command.phone()),
                command.password(), command.email(),
                (email, hash) -> User.newClient(ids.next(), command.fullName(), email, hash, command.phone(),
                        clock.instant()));
    }

    @Override
    public Created createOwner(CreateOwnerCommand command, String idempotencyKey) {
        return createOnce(idempotencyKey, CREATE_OWNER_OPERATION,
                requestHash(command.fullName(), command.email(), command.password(), command.phone(),
                        String.valueOf(command.barbershopId())),
                command.password(), command.email(),
                (email, hash) -> User.newOwner(ids.next(), command.barbershopId(), command.fullName(), email, hash,
                        command.phone(), clock.instant()));
    }

    @Override
    public Created createBarber(CreateBarberCommand command, UUID ownerBarbershopId, String idempotencyKey) {
        return createOnce(idempotencyKey, CREATE_BARBER_OPERATION,
                requestHash(command.fullName(), command.email(), command.password(), command.phone(),
                        String.valueOf(ownerBarbershopId)),
                command.password(), command.email(),
                (email, hash) -> User.newBarber(ids.next(), ownerBarbershopId, command.fullName(), email, hash,
                        command.phone(), clock.instant()));
    }

    /**
     * Creates an account once per Idempotency-Key: a retry with the same key and body returns the
     * first account and creates nothing; the same key with another body is refused.
     */
    private Created createOnce(String idempotencyKey, String operation, String requestHash, String password,
                               String rawEmail, BiFunction<String, String, User> build) {
        Optional<UserRepository.StoredKey> stored = users.findKey(idempotencyKey, operation);
        if (stored.isPresent()) {
            if (!stored.get().requestHash().equals(requestHash)) {
                throw new IdempotencyKeyReused();
            }
            return new Created(users.findById(stored.get().resourceId()).orElseThrow(), false);
        }

        PasswordPolicy.check(password);
        String email = User.normalizeEmail(rawEmail);
        if (users.findByEmail(email).isPresent()) {
            throw new BusinessRuleViolation("The email is already registered");
        }
        User user = build.apply(email, hasher.hash(password));
        try {
            users.saveNew(user, new IdempotencyRecord(idempotencyKey, operation, requestHash));
        } catch (UserRepository.EmailAlreadyTaken e) {
            throw new BusinessRuleViolation(e.getMessage());
        }
        // A second transaction: if it fails the account exists without a code, and "resend" sends one.
        sendVerification(user);
        return new Created(user, true);
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
        if (!user.emailVerified()) {
            throw new EmailNotVerified();          // only after the right password: DEC-AUTH-02 still holds
        }
        return authenticate(user, false);
    }

    @Override
    public AuthResult refresh(String refreshToken) {
        Instant now = clock.instant();
        UUID userId = refreshTokens.use(refreshToken, now).orElseThrow(InvalidCredentials::new);
        User user = users.findById(userId).filter(User::active).orElseThrow(InvalidCredentials::new);
        return authenticate(user, false);
    }

    @Override
    public void logout(UUID userId, String refreshToken, boolean allDevices) {
        Instant now = clock.instant();
        if (allDevices) {
            refreshTokens.revokeAll(userId, null, now);
        } else if (refreshToken != null) {
            refreshTokens.revoke(userId, refreshToken, now);
        }
    }

    @Override
    public AuthResult confirmEmail(String email, String code) {
        Instant now = clock.instant();
        User user = normalized(email).flatMap(users::findByEmail).filter(User::active)
                .orElseThrow(AuthService::invalidCode);
        VerificationCode match = verifications.usableVerifications(user.id(), now).stream()
                .filter(c -> code != null && hasher.matches(code, c.codeHash()))
                .findFirst().orElseThrow(AuthService::invalidCode);
        if (!verifications.consumeVerification(match.id(), user.id(), now)) {
            throw invalidCode();
        }
        return authenticate(user.verifiedAt(now), false);
    }

    @Override
    public void resendVerification(String email) {
        Instant now = clock.instant();
        Optional<User> user = normalized(email).flatMap(users::findByEmail)
                .filter(User::active).filter(u -> !u.emailVerified());
        if (user.isEmpty()
                || verifications.verificationsSince(user.get().id(), now.minus(RESEND_GAP)) > 0
                || verifications.verificationsSince(user.get().id(), now.minus(Duration.ofHours(1))) >= RESENDS_PER_HOUR) {
            return;                                  // 202 either way: says nothing about the account
        }
        sendVerification(user.get());
    }

    @Override
    public User me(UUID userId) {
        return users.findById(userId).orElseThrow(UserNotFound::new);
    }

    @Override
    public User updateMe(UUID userId, String fullName, String phone, boolean phoneSent) {
        User user = me(userId);
        User updated = user.withProfile(fullName != null ? fullName : user.fullName(),
                phoneSent ? phone : user.phone());
        users.update(updated, clock.instant());
        return updated;
    }

    @Override
    public void changePassword(UUID userId, String currentPassword, String newPassword, String keepRefreshToken) {
        User user = me(userId);
        if (currentPassword == null || !hasher.matches(currentPassword, user.passwordHash())) {
            throw new BusinessRuleViolation("The current password is incorrect");
        }
        PasswordPolicy.check(newPassword);
        Instant now = clock.instant();
        users.update(user.withPasswordHash(hasher.hash(newPassword)), now);
        refreshTokens.revokeAll(userId, keepRefreshToken, now);
    }

    /** The code and its EmailVerificationRequested commit together (DEC-AUTH-09); the code only as a hash. */
    private void sendVerification(User user) {
        String code = codes.next();
        Instant now = clock.instant();
        Instant expiresAt = now.plus(VERIFICATION_LIFETIME);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("userId", user.id().toString());
        payload.put("email", user.email());
        payload.put("fullName", user.fullName());
        payload.put("code", code);
        payload.put("expiresAt", expiresAt.toString());
        verifications.saveVerification(new VerificationCode(ids.next(), user.id(), hasher.hash(code), expiresAt, now),
                new OutboxEvent(ids.next(), user.id(), VERIFICATION_EVENT, payload, now));
    }

    private static Optional<String> normalized(String email) {
        try {
            return Optional.of(User.normalizeEmail(email));
        } catch (BusinessRuleViolation e) {
            return Optional.empty();
        }
    }

    /** One message for an unknown e-mail, a wrong code, an expired one and a used one. */
    private static BusinessRuleViolation invalidCode() {
        return new BusinessRuleViolation("The code is invalid or has expired");
    }

    /**
     * The caller's token already says CLIENT; the account is read again so a deactivated one gets
     * nothing. Nothing is stored: the binding lives only in the token (DEC-AUTH-06).
     */
    @Override
    public BarbershopToken issueBarbershopToken(UUID clientId, UUID barbershopId) {
        User client = users.findById(clientId)
                .filter(User::active)
                .filter(u -> u.role() == Role.CLIENT)
                .orElseThrow(InvalidCredentials::new);
        if (!barbershops.isOpen(barbershopId)) {
            throw new BarbershopNotFound();
        }
        TokenIssuer.IssuedToken token = tokens.issueBound(client, barbershopId, clock.instant(),
                BARBERSHOP_TOKEN_LIFETIME);
        return new BarbershopToken(token.token(), token.expiresInSeconds(), barbershopId);
    }

    @Override
    public User findUser(UUID id) {
        return users.findById(id).orElseThrow(UserNotFound::new);
    }

    @Override
    public List<User> findOwners(UUID barbershopId) {
        return users.findActiveOwners(barbershopId);
    }

    private AuthResult authenticate(User user, boolean created) {
        Instant now = clock.instant();
        TokenIssuer.IssuedToken access = tokens.issue(user, now);
        String refresh = refreshTokens.issueFor(user.id(), now);
        return new AuthResult(access.token(), refresh, access.expiresInSeconds(), user, created);
    }

    /** The same hash register always stored: the fields joined with a NUL, so old keys still match. */
    private static String requestHash(String... fields) {
        String[] values = new String[fields.length];
        for (int i = 0; i < fields.length; i++) {
            values[i] = String.valueOf(fields[i]);
        }
        return sha256(String.join(String.valueOf(SEPARATOR), values));
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
