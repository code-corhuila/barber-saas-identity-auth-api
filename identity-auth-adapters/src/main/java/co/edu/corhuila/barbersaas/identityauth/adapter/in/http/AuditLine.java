package co.edu.corhuila.barbersaas.identityauth.adapter.in.http;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.spi.LoggingEventBuilder;

/**
 * docs#168: who changed a password or created a barber, when and from where. One line per success in a
 * logger of its own, called only after the use case returns, so a refused request writes nothing. It takes
 * identifiers only, so it cannot carry a password, a code or a token. The log line's own timestamp is the time.
 */
final class AuditLine {

    static final String PASSWORD_CHANGED = "password.changed";
    static final String PASSWORD_RESET = "password.reset";
    static final String BARBER_CREATED = "barber.created";

    private static final Logger log = LoggerFactory.getLogger("audit");

    private AuditLine() { }

    static void write(HttpServletRequest request, String action, UUID userId, UUID barbershopId, String actor) {
        LoggingEventBuilder line = log.atInfo().setMessage(action)
                .addKeyValue("action", action)
                .addKeyValue("user_id", userId)
                .addKeyValue("trace_id", MDC.get(CorrelationFilter.MDC_KEY))
                .addKeyValue("source_ip", sourceIp(request));
        if (barbershopId != null) {
            line = line.addKeyValue("barbershopId", barbershopId);
        }
        if (actor != null) {
            line = line.addKeyValue("actor", actor);
        }
        line.log();
    }

    /** The gateway appends the client it saw last; anything before that was sent by the client. */
    private static String sourceIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            return request.getRemoteAddr();
        }
        return forwarded.substring(forwarded.lastIndexOf(',') + 1).trim();
    }
}
