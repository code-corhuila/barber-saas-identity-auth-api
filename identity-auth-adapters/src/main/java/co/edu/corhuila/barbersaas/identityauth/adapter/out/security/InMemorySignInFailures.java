package co.edu.corhuila.barbersaas.identityauth.adapter.out.security;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.SignInFailures;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Failed sign-ins kept in this process (docs#155): the platform runs one identity-auth-api per host
 * (ADR-019), and a restart only gives an attacker a fresh window. Times older than {@code keep} are
 * dropped on every write, and the whole map is pruned when it grows past {@code maxEmails}, so a flood
 * of random e-mails cannot fill the memory.
 */
public class InMemorySignInFailures implements SignInFailures {

    private final Map<String, Deque<Instant>> byEmail = new ConcurrentHashMap<>();
    private final Duration keep;
    private final int maxEmails;

    public InMemorySignInFailures(Duration keep, int maxEmails) {
        this.keep = keep;
        this.maxEmails = maxEmails;
    }

    @Override
    public int countSince(String email, Instant since) {
        Deque<Instant> times = byEmail.get(email);
        if (times == null) {
            return 0;
        }
        synchronized (times) {
            return (int) times.stream().filter(t -> !t.isBefore(since)).count();
        }
    }

    @Override
    public void record(String email, Instant at) {
        if (byEmail.size() >= maxEmails) {
            prune(at);
        }
        Deque<Instant> times = byEmail.computeIfAbsent(email, k -> new ArrayDeque<>());
        synchronized (times) {
            times.addLast(at);
            dropOld(times, at);
        }
    }

    @Override
    public void clear(String email) {
        byEmail.remove(email);
    }

    private void prune(Instant now) {
        byEmail.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                dropOld(e.getValue(), now);
                return e.getValue().isEmpty();
            }
        });
        if (byEmail.size() >= maxEmails) {
            byEmail.clear();                     // still full of live entries: start again rather than grow
        }
    }

    private void dropOld(Deque<Instant> times, Instant now) {
        Instant limit = now.minus(keep);
        while (!times.isEmpty() && times.peekFirst().isBefore(limit)) {
            times.pollFirst();
        }
    }
}
