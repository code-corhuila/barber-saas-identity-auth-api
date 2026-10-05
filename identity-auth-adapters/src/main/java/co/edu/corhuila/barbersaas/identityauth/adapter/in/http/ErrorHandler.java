package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ForbiddenException;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.ApiError.ValidationException;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.BarbershopNotFound;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.IdempotencyKeyReused;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.InvalidCredentials;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases.UserNotFound;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.Barbershops;
import co.edu.corhuila.barbersaas.identityauth.domain.model.DomainException.BusinessRuleViolation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/** The ONLY place where errors become status codes. Every error answers with the envelope. */
@RestControllerAdvice
public class ErrorHandler {

    private static final Logger log = LoggerFactory.getLogger(ErrorHandler.class);

    @ExceptionHandler(ValidationException.class)
    ResponseEntity<ApiError> validation(ValidationException e) {
        return respond(HttpStatus.BAD_REQUEST, ApiError.of(ApiError.VALIDATION_ERROR, e.getMessage(), e.details()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ApiError> unreadable(HttpMessageNotReadableException e) {
        return respond(HttpStatus.BAD_REQUEST, ApiError.of(ApiError.VALIDATION_ERROR, "the body is not valid JSON"));
    }

    @ExceptionHandler(InvalidCredentials.class)
    ResponseEntity<ApiError> invalidCredentials(InvalidCredentials e) {
        return respond(HttpStatus.UNAUTHORIZED, ApiError.of(ApiError.UNAUTHORIZED, e.getMessage()));
    }

    @ExceptionHandler(ForbiddenException.class)
    ResponseEntity<ApiError> forbidden(ForbiddenException e) {
        return respond(HttpStatus.FORBIDDEN, ApiError.of(ApiError.FORBIDDEN, e.getMessage()));
    }

    @ExceptionHandler({BusinessRuleViolation.class, IdempotencyKeyReused.class})
    ResponseEntity<ApiError> businessRule(RuntimeException e) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, ApiError.of(ApiError.BUSINESS_RULE_VIOLATION, e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    ResponseEntity<ApiError> badPathValue(MethodArgumentTypeMismatchException e) {
        return respond(HttpStatus.BAD_REQUEST, ApiError.of(ApiError.VALIDATION_ERROR, "the request is not valid",
                java.util.List.of(new ApiError.FieldError(e.getName(), "not a valid value"))));
    }

    @ExceptionHandler(UserNotFound.class)
    ResponseEntity<ApiError> userNotFound(UserNotFound e) {
        return respond(HttpStatus.NOT_FOUND, ApiError.of(ApiError.NOT_FOUND, e.getMessage()));
    }

    @ExceptionHandler(BarbershopNotFound.class)
    ResponseEntity<ApiError> barbershopNotFound(BarbershopNotFound e) {
        return respond(HttpStatus.NOT_FOUND, ApiError.of(ApiError.NOT_FOUND, e.getMessage()));
    }

    /** barbershop-api could not be asked (DEC-AUTH-06): logged, and no token is issued. */
    @ExceptionHandler(Barbershops.Unavailable.class)
    ResponseEntity<ApiError> barbershopsUnavailable(Barbershops.Unavailable e) {
        log.warn("barbershop check failed: {}", e.getMessage());
        return respond(HttpStatus.SERVICE_UNAVAILABLE,
                ApiError.of(ApiError.SERVICE_UNAVAILABLE, "The barbershop could not be checked, try again"));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    ResponseEntity<ApiError> noRoute(NoResourceFoundException e) {
        return respond(HttpStatus.NOT_FOUND, ApiError.of(ApiError.NOT_FOUND, "no such route"));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    ResponseEntity<ApiError> method(HttpRequestMethodNotSupportedException e) {
        return respond(HttpStatus.METHOD_NOT_ALLOWED, ApiError.of(ApiError.NOT_FOUND, "method not allowed on this route"));
    }

    /** Logged in full (the MDC adds the correlation id); the client gets a neutral text. */
    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> unexpected(Exception e) {
        log.error("unhandled error", e);
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, ApiError.of(ApiError.INTERNAL_ERROR, "unexpected error"));
    }

    private static ResponseEntity<ApiError> respond(HttpStatus status, ApiError body) {
        return ResponseEntity.status(status).body(body);
    }
}
