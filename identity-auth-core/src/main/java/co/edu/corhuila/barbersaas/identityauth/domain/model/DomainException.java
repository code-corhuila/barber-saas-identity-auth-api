package co.edu.corhuila.barbersaas.identityauth.domain.model;

/** Errors the domain raises. The HTTP adapter turns each into one status code. */
public abstract class DomainException extends RuntimeException {

    protected DomainException(String message) {
        super(message);
    }

    /** An input that breaks an invariant: 422 BUSINESS_RULE_VIOLATION. */
    public static class BusinessRuleViolation extends DomainException {
        public BusinessRuleViolation(String message) {
            super(message);
        }
    }
}
