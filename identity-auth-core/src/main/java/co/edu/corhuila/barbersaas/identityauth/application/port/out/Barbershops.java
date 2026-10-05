package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import java.util.UUID;

/** The barbershop domain, asked whether a client may bind a token to a barbershop (DEC-AUTH-06). */
public interface Barbershops {

    /**
     * True when the barbershop exists and is ACTIVE or TRIAL; false when it does not exist or is
     * SUSPENDED or CANCELLED.
     *
     * @throws Unavailable when barbershop-api does not answer, so the check could not be made
     */
    boolean isOpen(UUID barbershopId);

    /** barbershop-api did not answer: 503, never a token. */
    class Unavailable extends RuntimeException {
        public Unavailable(String message) {
            super(message);
        }

        public Unavailable(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
