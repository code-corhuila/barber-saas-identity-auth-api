package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.FieldError;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ForbiddenException;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ValidationException;
import co.edu.corhuila.barbersaas.identityauth.adapter.out.security.Rs256TokenIssuer;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.AuthResult;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.BarbershopToken;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.CreateBarberCommand;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.Created;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.RegisterCommand;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** HTTP to use case for auth-service.yaml: validates the shape, never decides business rules. */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    public record RegisterRequest(String fullName, String email, String password, String phone) { }

    public record LoginRequest(String email, String password) { }

    /** No barbershopId and no role: both come from the owner's token. */
    public record CreateBarberRequest(String fullName, String email, String password, String phone) { }

    public record UserSummary(UUID id, String fullName, String email, String phone, String profilePhotoUrl,
                              String role, UUID barbershopId, boolean isActive) {
        static UserSummary of(User u) {
            return new UserSummary(u.id(), u.fullName(), u.email(), u.phone(), u.profilePhotoUrl(),
                    u.role().name(), u.barbershopId(), u.active());
        }
    }

    public record AuthResponse(String accessToken, String refreshToken, long expiresIn, UserSummary user) {
        static AuthResponse of(AuthResult r) {
            return new AuthResponse(r.accessToken(), r.refreshToken(), r.expiresIn(), UserSummary.of(r.user()));
        }
    }

    /** The barbershop the client picked in the anonymous catalog (DEC-AUTH-06). */
    public record BarbershopTokenRequest(UUID barbershopId) { }

    /** No refresh token: the platform session keeps its own. */
    public record BarbershopTokenResponse(String accessToken, long expiresIn, UUID barbershopId) {
        static BarbershopTokenResponse of(BarbershopToken t) {
            return new BarbershopTokenResponse(t.accessToken(), t.expiresIn(), t.barbershopId());
        }
    }

    private final AuthUseCases auth;
    private final Rs256TokenIssuer keys;

    public AuthController(AuthUseCases auth, Rs256TokenIssuer keys) {
        this.auth = auth;
        this.keys = keys;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestBody(required = false) RegisterRequest body) {
        List<FieldError> errors = new ArrayList<>();
        requireIdempotencyKey(errors, idempotencyKey);
        if (body == null) {
            throw new ValidationException("the body is required", errors);
        }
        requireAccountFields(errors, body.fullName(), body.email(), body.password(), body.phone());
        if (!errors.isEmpty()) {
            throw new ValidationException("the request is not valid", errors);
        }
        AuthResult result = auth.register(
                new RegisterCommand(body.fullName(), body.email(), body.password(), body.phone()), idempotencyKey);
        if (!result.created()) {
            return ResponseEntity.ok(AuthResponse.of(result));
        }
        return ResponseEntity.status(HttpStatus.CREATED)
                .location(URI.create("/api/v1/users/" + result.user().id()))
                .body(AuthResponse.of(result));
    }

    /** Role ADMIN_BARBERSHOP; the barber joins the barbershop of the owner's token (DEC-AUTH-05). */
    @PostMapping("/barbers")
    public ResponseEntity<UserSummary> createBarber(
            HttpServletRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestBody(required = false) CreateBarberRequest body) {
        Caller caller = AuthFilter.caller(request);
        if (!caller.hasRole("ADMIN_BARBERSHOP") || caller.barbershopId() == null) {
            throw new ForbiddenException();
        }
        List<FieldError> errors = new ArrayList<>();
        requireIdempotencyKey(errors, idempotencyKey);
        if (body == null) {
            throw new ValidationException("the body is required", errors);
        }
        requireAccountFields(errors, body.fullName(), body.email(), body.password(), body.phone());
        if (!errors.isEmpty()) {
            throw new ValidationException("the request is not valid", errors);
        }
        Created result = auth.createBarber(
                new CreateBarberCommand(body.fullName(), body.email(), body.password(), body.phone()),
                caller.barbershopId(), idempotencyKey);
        if (!result.created()) {
            return ResponseEntity.ok(UserSummary.of(result.user()));
        }
        return ResponseEntity.status(HttpStatus.CREATED)
                .location(URI.create("/api/v1/users/" + result.user().id()))
                .body(UserSummary.of(result.user()));
    }

    /**
     * Role CLIENT (DEC-AUTH-06), with a platform token or one bound to another barbershop. The only
     * operation whose body carries a barbershopId: choosing the tenant is what it does.
     */
    @PostMapping("/barbershop-token")
    public BarbershopTokenResponse barbershopToken(HttpServletRequest request,
                                                   @RequestBody(required = false) BarbershopTokenRequest body) {
        Caller caller = AuthFilter.caller(request);
        if (!caller.hasRole("CLIENT")) {
            throw new ForbiddenException();
        }
        if (body == null || body.barbershopId() == null) {
            throw new ValidationException("the request is not valid",
                    List.of(new FieldError("barbershopId", "required")));
        }
        return BarbershopTokenResponse.of(
                auth.issueBarbershopToken(UUID.fromString(caller.subject()), body.barbershopId()));
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody(required = false) LoginRequest body) {
        List<FieldError> errors = new ArrayList<>();
        if (body == null) {
            throw new ValidationException("the body is required", errors);
        }
        requireText(errors, "email", body.email(), 150);
        requireText(errors, "password", body.password(), 100);
        if (!errors.isEmpty()) {
            throw new ValidationException("the request is not valid", errors);
        }
        return AuthResponse.of(auth.login(body.email(), body.password()));
    }

    /** RFC 7517 key set every service validates tokens with (norm 5.3.7). */
    @GetMapping("/jwks")
    public Map<String, Object> jwks() {
        return Map.of("keys", List.of(keys.jwk()));
    }

    static void requireIdempotencyKey(List<FieldError> errors, String idempotencyKey) {
        if (idempotencyKey == null || idempotencyKey.length() < 8 || idempotencyKey.length() > 128) {
            errors.add(new FieldError("Idempotency-Key", "required, between 8 and 128 characters"));
        }
    }

    /** The fields every account is created with: register, owners and barbers. */
    static void requireAccountFields(List<FieldError> errors, String fullName, String email, String password,
                                     String phone) {
        requireText(errors, "fullName", fullName, 120);
        requireText(errors, "email", email, 150);
        requireText(errors, "password", password, 100);
        if (phone != null && phone.length() > 20) {
            errors.add(new FieldError("phone", "at most 20 characters"));
        }
    }

    static void requireText(List<FieldError> errors, String field, String value, int max) {
        if (value == null || value.isBlank()) {
            errors.add(new FieldError(field, "required"));
        } else if (value.length() > max) {
            errors.add(new FieldError(field, "at most " + max + " characters"));
        }
    }
}
