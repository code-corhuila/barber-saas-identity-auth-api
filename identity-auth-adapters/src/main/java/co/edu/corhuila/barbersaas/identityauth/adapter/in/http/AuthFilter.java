package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Set;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/** Validates the bearer token on every protected route under /api/ and on every /internal/ route. */
public class AuthFilter extends OncePerRequestFilter {

    public static final String CALLER_ATTRIBUTE = "auth.caller";

    /** Operations under /api/v1/auth/ that need a token; the rest of that path is how a token is obtained. */
    private static final Set<String> PROTECTED_AUTH_PATHS = Set.of("/api/v1/auth/logout", "/api/v1/auth/barbers");

    /** The caller the filter verified. Only called on routes the filter protects. */
    public static Caller caller(HttpServletRequest request) {
        return (Caller) request.getAttribute(CALLER_ATTRIBUTE);
    }

    private final Rs256Verifier verifier;
    private final ObjectMapper json;

    public AuthFilter(Rs256Verifier verifier, ObjectMapper json) {
        this.verifier = verifier;
        this.json = json;
    }

    /**
     * The public operations of auth-service.yaml are the way to obtain a token. Internal operations
     * are never public: the gateway does not route them, and this service still asks for a token.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.startsWith("/internal/")) {
            return false;
        }
        if (!path.startsWith("/api/")) {
            return true;
        }
        return path.startsWith("/api/v1/auth/") && !PROTECTED_AUTH_PATHS.contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ") || header.length() == 7) {
            reject(response, "a bearer token is required");
            return;
        }
        try {
            request.setAttribute(CALLER_ATTRIBUTE, verifier.verify(header.substring(7), Instant.now()));
        } catch (Rs256Verifier.InvalidTokenException e) {
            reject(response, "the token is invalid or has expired");
            return;
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        json.writeValue(response.getOutputStream(), ApiError.of(ApiError.UNAUTHORIZED, message));
    }
}
