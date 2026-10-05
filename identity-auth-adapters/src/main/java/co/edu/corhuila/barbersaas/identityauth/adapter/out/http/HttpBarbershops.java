package co.edu.corhuila.barbersaas.identityauth.adapter.out.http;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.Barbershops;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;

/**
 * Asks barbershop-api on the internal network with its anonymous discovery read
 * {@code GET /api/v1/barbershops/{id}}, which answers 200 only for an ACTIVE or TRIAL barbershop
 * and 404 otherwise (barbershop-service.yaml DEC-SHOP-02). Anything else is Unavailable: a token is
 * never issued without the check.
 */
public class HttpBarbershops implements Barbershops {

    private static final Duration TIMEOUT = Duration.ofSeconds(3);

    private final String baseUrl;
    private final HttpClient http;

    public HttpBarbershops(String baseUrl) {
        this.baseUrl = baseUrl == null ? "" : baseUrl.replaceAll("/+$", "");
        this.http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    }

    @Override
    public boolean isOpen(UUID barbershopId) {
        if (baseUrl.isBlank()) {
            throw new Unavailable("BARBERSHOP_API_URL is not set");
        }
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/api/v1/barbershops/" + barbershopId))
                .timeout(TIMEOUT).GET().build();
        int status;
        try {
            status = http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (IOException e) {
            throw new Unavailable("barbershop-api did not answer", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Unavailable("interrupted while asking barbershop-api", e);
        }
        if (status == 200) {
            return true;
        }
        if (status == 404) {
            return false;
        }
        throw new Unavailable("barbershop-api answered " + status);
    }
}
