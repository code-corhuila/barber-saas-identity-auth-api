package co.edu.corhuila.barbersaas.identityauth.adapter.out.persistence;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Used when DATABASE_URL is empty: the service starts and its HTTP contract can be tested without a database. */
public class InMemoryUserRepository implements UserRepository {

    private final Map<UUID, User> users = new ConcurrentHashMap<>();
    private final Map<String, StoredKey> keys = new ConcurrentHashMap<>();

    @Override
    public Optional<User> findByEmail(String normalizedEmail) {
        return users.values().stream().filter(u -> u.email().equals(normalizedEmail)).findFirst();
    }

    @Override
    public Optional<User> findById(UUID id) {
        return Optional.ofNullable(users.get(id));
    }

    @Override
    public Optional<StoredKey> findKey(String key, String operation) {
        return Optional.ofNullable(keys.get(operation + " " + key));
    }

    @Override
    public synchronized void saveNew(User user, IdempotencyRecord key) {
        if (findByEmail(user.email()).isPresent()) {
            throw new EmailAlreadyTaken();
        }
        users.put(user.id(), user);
        keys.put(key.operation() + " " + key.key(), new StoredKey(user.id(), key.requestHash()));
    }
}
