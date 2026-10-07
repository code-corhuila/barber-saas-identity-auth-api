package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import static co.edu.corhuila.barbersaas.identityauth.adapter.in.http.AuthController.requireText;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.FieldError;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ValidationException;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.PasswordResetUseCases;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Tag Password of auth-service.yaml: public, like login (DEC-AUTH-03). */
@RestController
@RequestMapping("/api/v1/auth/password-reset")
public class PasswordController {

    private static final Pattern CODE = Pattern.compile("^\\d{6}$");

    public record ResetRequest(String email) { }

    public record ConfirmRequest(String email, String code, String newPassword) { }

    private final PasswordResetUseCases resets;

    public PasswordController(PasswordResetUseCases resets) {
        this.resets = resets;
    }

    /** Always 202 for a well-formed body, whether the e-mail exists or not. */
    @PostMapping
    public ResponseEntity<Void> request(@RequestBody(required = false) ResetRequest body) {
        List<FieldError> errors = new ArrayList<>();
        if (body == null) {
            throw new ValidationException("the body is required", errors);
        }
        requireText(errors, "email", body.email(), 150);
        if (!errors.isEmpty()) {
            throw new ValidationException("the request is not valid", errors);
        }
        resets.request(body.email());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/confirm")
    public ResponseEntity<Void> confirm(@RequestBody(required = false) ConfirmRequest body) {
        List<FieldError> errors = new ArrayList<>();
        if (body == null) {
            throw new ValidationException("the body is required", errors);
        }
        requireText(errors, "email", body.email(), 150);
        if (body.code() == null || !CODE.matcher(body.code()).matches()) {
            errors.add(new FieldError("code", "must be 6 digits"));
        }
        requireText(errors, "newPassword", body.newPassword(), 100);
        if (!errors.isEmpty()) {
            throw new ValidationException("the request is not valid", errors);
        }
        resets.confirm(body.email(), body.code(), body.newPassword());
        return ResponseEntity.noContent().build();
    }
}
