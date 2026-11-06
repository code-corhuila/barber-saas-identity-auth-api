package co.edu.corhuila.barbersaas.identityauth.application.port.in;

import co.edu.corhuila.barbersaas.identityauth.domain.model.User;

/** Password recovery with an e-mailed code (HU-AUTH-002, DEC-AUTH-03, DEC-AUTH-08). */
public interface PasswordResetUseCases {

    /** Never tells whether the e-mail exists: the code is written to the outbox only for an active account. */
    void request(String email);

    /** Sets the new password and returns the account; an invalid, expired or used code is a BusinessRuleViolation (422). */
    User confirm(String email, String code, String newPassword);
}
