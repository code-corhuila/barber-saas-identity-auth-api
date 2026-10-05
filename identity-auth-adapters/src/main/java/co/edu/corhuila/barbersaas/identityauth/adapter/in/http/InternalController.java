package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.FieldError;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ForbiddenException;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ValidationException;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.AuthController.UserSummary;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.CreateOwnerCommand;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.Created;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Operations for other services (auth-service.yaml, tag Internal). The gateway never routes
 * /internal/; each operation accepts only the service token of the one service that calls it.
 */
@RestController
@RequestMapping("/internal/v1")
public class InternalController {

    /** The only caller of createOwner: the owner-onboarding saga (DEC-AUTH-04). */
    static final String WORKFLOW = "barber-saas-workflow";

    public record CreateOwnerRequest(String fullName, String email, String password, String phone,
                                     UUID barbershopId) { }

    private final AuthUseCases auth;

    public InternalController(AuthUseCases auth) {
        this.auth = auth;
    }

    @PostMapping("/owners")
    public ResponseEntity<UserSummary> createOwner(
            HttpServletRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestBody(required = false) CreateOwnerRequest body) {
        if (!AuthFilter.caller(request).isService(WORKFLOW)) {
            throw new ForbiddenException();
        }
        List<FieldError> errors = new ArrayList<>();
        AuthController.requireIdempotencyKey(errors, idempotencyKey);
        if (body == null) {
            throw new ValidationException("the body is required", errors);
        }
        AuthController.requireAccountFields(errors, body.fullName(), body.email(), body.password(), body.phone());
        if (body.barbershopId() == null) {
            errors.add(new FieldError("barbershopId", "required"));
        }
        if (!errors.isEmpty()) {
            throw new ValidationException("the request is not valid", errors);
        }
        Created result = auth.createOwner(new CreateOwnerCommand(body.fullName(), body.email(), body.password(),
                body.phone(), body.barbershopId()), idempotencyKey);
        if (!result.created()) {
            return ResponseEntity.ok(UserSummary.of(result.user()));
        }
        return ResponseEntity.status(HttpStatus.CREATED)
                .location(URI.create("/api/v1/users/" + result.user().id()))
                .body(UserSummary.of(result.user()));
    }
}
