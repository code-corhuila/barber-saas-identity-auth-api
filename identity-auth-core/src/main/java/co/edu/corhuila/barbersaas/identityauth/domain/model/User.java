package co.edu.corhuila.barbersaas.identityauth.domain.model;

import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/** An account of identity_auth.app_user. Never exposes or logs the password hash. */
public final class User {

    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private final UUID id;
    private final UUID barbershopId;
    private final String fullName;
    private final String email;
    private final String passwordHash;
    private final String phone;
    private final String profilePhotoUrl;
    private final Role role;
    private final boolean active;
    private final Instant createdAt;

    public User(UUID id, UUID barbershopId, String fullName, String email, String passwordHash, String phone,
                String profilePhotoUrl, Role role, boolean active, Instant createdAt) {
        this.id = Objects.requireNonNull(id);
        this.role = Objects.requireNonNull(role);
        if (role.requiresTenant() != (barbershopId != null)) {
            throw new BusinessRuleViolation("Only barbershop staff belongs to a barbershop");
        }
        this.barbershopId = barbershopId;
        this.fullName = requireFullName(fullName);
        this.email = normalizeEmail(email);
        this.passwordHash = Objects.requireNonNull(passwordHash);
        if (phone != null && phone.length() > 20) {
            throw new BusinessRuleViolation("The phone has at most 20 characters");
        }
        this.phone = phone == null || phone.isBlank() ? null : phone.strip();
        this.profilePhotoUrl = profilePhotoUrl;
        this.active = active;
        this.createdAt = Objects.requireNonNull(createdAt);
    }

    /** Self-registration always creates a CLIENT without a barbershop (DEC-AUTH-01). */
    public static User newClient(UUID id, String fullName, String email, String passwordHash, String phone,
                                 Instant now) {
        return new User(id, null, fullName, email, passwordHash, phone, null, Role.CLIENT, true, now);
    }

    /**
     * The owner of a barbershop the onboarding saga has just created (DEC-AUTH-04). The constructor
     * refuses it without a barbershop (chk_app_user_tenant).
     */
    public static User newOwner(UUID id, UUID barbershopId, String fullName, String email, String passwordHash,
                                String phone, Instant now) {
        return new User(id, barbershopId, fullName, email, passwordHash, phone, null, Role.ADMIN_BARBERSHOP, true,
                now);
    }

    /** A barber an owner adds to their own barbershop, with an initial password (DEC-AUTH-05). */
    public static User newBarber(UUID id, UUID barbershopId, String fullName, String email, String passwordHash,
                                 String phone, Instant now) {
        return new User(id, barbershopId, fullName, email, passwordHash, phone, null, Role.BARBER, true, now);
    }

    /** E-mails are compared case-insensitively (uq_app_user_email is on lower(email)). */
    public static String normalizeEmail(String email) {
        if (email == null) {
            throw new BusinessRuleViolation("The e-mail is required");
        }
        String e = email.strip().toLowerCase(Locale.ROOT);
        if (e.length() > 150 || !EMAIL.matcher(e).matches()) {
            throw new BusinessRuleViolation("The e-mail is not valid");
        }
        return e;
    }

    private static String requireFullName(String fullName) {
        String n = fullName == null ? "" : fullName.strip();
        if (n.isEmpty() || n.length() > 120) {
            throw new BusinessRuleViolation("The full name must have between 1 and 120 characters");
        }
        return n;
    }

    public UUID id() { return id; }
    public UUID barbershopId() { return barbershopId; }
    public String fullName() { return fullName; }
    public String email() { return email; }
    public String passwordHash() { return passwordHash; }
    public String phone() { return phone; }
    public String profilePhotoUrl() { return profilePhotoUrl; }
    public Role role() { return role; }
    public boolean active() { return active; }
    public Instant createdAt() { return createdAt; }
}
