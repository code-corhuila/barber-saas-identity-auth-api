package co.edu.corhuila.barbersaas.identityauth.adapter.out.security;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.ResetCodes;
import java.security.SecureRandom;

/** Six digits from a SecureRandom, leading zeros kept (auth-service.yaml: code ^\d{6}$). */
public class RandomResetCodes implements ResetCodes {

    private final SecureRandom random = new SecureRandom();

    @Override
    public String next() {
        return String.format("%06d", random.nextInt(1_000_000));
    }
}
