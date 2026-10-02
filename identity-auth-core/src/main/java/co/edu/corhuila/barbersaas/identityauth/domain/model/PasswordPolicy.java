package co.edu.corhuila.barbersaas.identityauth.domain.model;

import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;

/** auth-service.yaml Password: 8 to 100 characters, at least one uppercase letter and one digit. */
public final class PasswordPolicy {

    private PasswordPolicy() {
    }

    public static void check(String raw) {
        if (raw == null || raw.length() < 8 || raw.length() > 100) {
            throw new BusinessRuleViolation("The password must have between 8 and 100 characters");
        }
        if (raw.chars().noneMatch(Character::isUpperCase) || raw.chars().noneMatch(Character::isDigit)) {
            throw new BusinessRuleViolation("The password needs at least one uppercase letter and one digit");
        }
    }
}
