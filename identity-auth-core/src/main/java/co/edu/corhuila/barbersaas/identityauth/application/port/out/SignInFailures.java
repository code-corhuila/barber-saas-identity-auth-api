package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import java.time.Instant;

/**
 * Failed sign-ins per e-mail (docs#155): counted for any e-mail, with or without an account, so the
 * lock does not reveal which accounts exist (docs#167).
 */
public interface SignInFailures {

    /** How many failed sign-ins the e-mail had at or after {@code since}. */
    int countSince(String email, Instant since);

    void record(String email, Instant at);

    /** A successful sign-in starts the count again. */
    void clear(String email);
}
