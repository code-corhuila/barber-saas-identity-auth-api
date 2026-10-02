package co.edu.corhuila.barbersaas.identityauth.application.port.out;

public interface PasswordHasher {

    String hash(String raw);

    boolean matches(String raw, String hash);
}
