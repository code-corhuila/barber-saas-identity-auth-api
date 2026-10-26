package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import static co.edu.corhuila.barbersaas.identityauth.adapter.in.http.AuthController.requireText;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.FieldError;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ValidationException;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.AuthController.AuthResponse;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E-mail verification (auth-service.yaml tag Verification, DEC-AUTH-09): public, like the password reset. */
@RestController
@RequestMapping("/api/v1/auth/email-verification")
public class VerificationController {

    private static final Pattern CODE = Pattern.compile("^\\d{6}$");

    public record ConfirmRequest(String email, String code) { }

    public record ResendRequest(String email) { }

    private final AuthUseCases auth;

    public VerificationController(AuthUseCases auth) {
        this.auth = auth;
    }

    /** Verified and signed in, with the same answer as login. */
    @PostMapping("/confirm")
    public AuthResponse confirm(@RequestBody(required = false) ConfirmRequest body) {
        List<FieldError> errors = new ArrayList<>();
        if (body == null) {
            throw new ValidationException("the body is required", errors);
        }
        requireText(errors, "email", body.email(), 150);
        if (body.code() == null || !CODE.matcher(body.code()).matches()) {
            errors.add(new FieldError("code", "must be 6 digits"));
        }
        if (!errors.isEmpty()) {
            throw new ValidationException("the request is not valid", errors);
        }
        return AuthResponse.of(auth.confirmEmail(body.email(), body.code()));
    }

    /** Always 202 for a well-formed body: it never says whether the account exists. */
    @PostMapping("/resend")
    public ResponseEntity<Void> resend(@RequestBody(required = false) ResendRequest body) {
        List<FieldError> errors = new ArrayList<>();
        if (body == null) {
            throw new ValidationException("the body is required", errors);
        }
        requireText(errors, "email", body.email(), 150);
        if (!errors.isEmpty()) {
            throw new ValidationException("the request is not valid", errors);
        }
        auth.resendVerification(body.email());
        return ResponseEntity.accepted().build();
    }
}
