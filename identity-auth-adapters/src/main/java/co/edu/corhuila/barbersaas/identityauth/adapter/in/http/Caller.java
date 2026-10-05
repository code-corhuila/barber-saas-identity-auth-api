package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import java.util.UUID;

/**
 * Who calls, read from a verified token (07-api/authentication.md): the subject, its role and,
 * for barbershop staff, the tenant. A service token carries {@code role: SERVICE} and the
 * service name as subject; an internal operation checks both.
 */
public record Caller(String subject, String role, UUID barbershopId) {

    public static final String SERVICE_ROLE = "SERVICE";

    public boolean isService(String serviceName) {
        return SERVICE_ROLE.equals(role) && serviceName.equals(subject);
    }

    public boolean hasRole(String expected) {
        return expected.equals(role);
    }
}
