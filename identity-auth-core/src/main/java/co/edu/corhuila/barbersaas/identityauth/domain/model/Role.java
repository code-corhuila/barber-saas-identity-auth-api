package co.edu.corhuila.barbersaas.identityauth.domain.model;

/** Exactly one per user (identity_auth.app_user.role). Same values as chk_app_user_role. */
public enum Role {
    SUPER_ADMIN, ADMIN_BARBERSHOP, BARBER, CLIENT;

    /** Only the barbershop staff belongs to one tenant (chk_app_user_tenant). */
    public boolean requiresTenant() {
        return this == ADMIN_BARBERSHOP || this == BARBER;
    }
}
