package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import java.util.UUID;

/**
 * Who calls, read from a verified token (07-api/authentication.md): the subject, its role and,
 * for barbershop staff, the tenant. A service token carries {@code role: SERVICE} and the
 * service name as subject; an internal operation checks both.
 */
public record Caller(String subject, String role, UUID barbershopId, java.util.Set<String> scopes) {

    public Caller {
        scopes = scopes == null ? java.util.Set.of() : java.util.Set.copyOf(scopes);
    }

    /** A caller whose token carries no scope. */
    public Caller(String subject, String role, UUID barbershopId) {
        this(subject, role, barbershopId, java.util.Set.of());
    }

    public static final String SERVICE_ROLE = "SERVICE";

    public boolean isService(String serviceName) {
        return SERVICE_ROLE.equals(role) && serviceName.equals(subject);
    }

    /** That service, and its token grants {@code scope} (07-api/authentication.md, Scopes; docs#159). */
    public boolean isService(String serviceName, String scope) {
        return isService(serviceName) && scopes.contains(scope);
    }

    public boolean hasRole(String expected) {
        return expected.equals(role);
    }
}
