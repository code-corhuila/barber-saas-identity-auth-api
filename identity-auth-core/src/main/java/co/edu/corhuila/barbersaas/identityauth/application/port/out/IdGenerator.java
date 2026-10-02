package co.edu.corhuila.barbersaas.identityauth.application.port.out;

import java.util.UUID;

public interface IdGenerator {

    UUID next();
}
