package co.edu.corhuila.barbersaas.identityauth.application.port.out;

/** Source of password-reset codes: six random digits (DEC-AUTH-03). */
public interface ResetCodes {

    String next();
}
