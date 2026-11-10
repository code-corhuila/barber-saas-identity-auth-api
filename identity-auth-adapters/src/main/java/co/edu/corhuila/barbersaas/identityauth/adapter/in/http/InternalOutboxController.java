package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.FieldError;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ForbiddenException;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ValidationException;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.OutboxRelayUseCases;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.OutboxRelayUseCases.EventEnvelope;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The outbox relay (tag Internal, DEC-AUTH-08, ADR-016), for barber-saas-worker on the internal
 * network: the api-gateway never routes /internal/v1.
 */
@RestController
@RequestMapping("/internal/v1/outbox-events")
public class InternalOutboxController {

    /** The only caller of the three operations. */
    static final String WORKER = "barber-saas-worker";

    public record PendingView(List<EventEnvelope> data) { }

    private final OutboxRelayUseCases relay;

    public InternalOutboxController(OutboxRelayUseCases relay) {
        this.relay = relay;
    }

    /** The largest batch: a stolen worker token reads every tenant's pending events only slowly (docs#160). */
    static final int MAX_LIMIT = 50;

    /** listPendingOutboxEvents: at most {@code limit} (1–50, default 20), oldest first. */
    @GetMapping
    public PendingView pending(HttpServletRequest request, @RequestParam(required = false) Integer limit) {
        requireWorker(request);
        if (limit != null && (limit < 1 || limit > MAX_LIMIT)) {
            throw new ValidationException("the request is not valid",
                    List.of(new FieldError("limit", "between 1 and " + MAX_LIMIT)));
        }
        return new PendingView(relay.pending(limit == null ? 20 : limit));
    }

    @PostMapping("/{id}/published")
    public ResponseEntity<Void> published(HttpServletRequest request, @PathVariable UUID id) {
        requireWorker(request);
        relay.published(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/failed")
    public ResponseEntity<Void> failed(HttpServletRequest request, @PathVariable UUID id,
                                       @RequestBody(required = false) Map<String, Object> body) {
        requireWorker(request);
        Object reason = body == null ? null : body.get("reason");
        if (body != null && body.keySet().stream().anyMatch(k -> !"reason".equals(k))) {
            throw new ValidationException("the request is not valid",
                    List.of(new FieldError("body", "only reason is accepted")));
        }
        if (!(reason instanceof String text) || text.isBlank() || text.length() > 500) {
            throw new ValidationException("the request is not valid",
                    List.of(new FieldError("reason", "between 1 and 500 characters")));
        }
        relay.failed(id, text);
        return ResponseEntity.noContent().build();
    }

    /** The worker's relay token: the reset codes travel here, so its scope is required (docs#159, docs#160). */
    static final String RELAY_SCOPE = "outbox:relay";

    private static void requireWorker(HttpServletRequest request) {
        if (!AuthFilter.caller(request).isService(WORKER, RELAY_SCOPE)) {
            throw new ForbiddenException();
        }
    }
}
