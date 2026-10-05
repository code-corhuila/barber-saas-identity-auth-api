package co.edu.corhuila.barbersaas.identityauth.adapter.out.security;

import co.edu.corhuila.barbersaas.identityauth.application.port.out.TokenIssuer;
import co.edu.corhuila.barbersaas.identityauth.domain.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Signs access tokens with RS256 and the claims of 07-api/authentication.md. The public half
 * is derived from the private key and published as JWKS, so there is one key to configure.
 */
public class Rs256TokenIssuer implements TokenIssuer {

    public static final String ISSUER = "barber-saas-identity-auth-api";

    private final RSAPrivateCrtKey key;
    private final String kid;
    private final long lifetimeSeconds;
    private final ObjectMapper json = new ObjectMapper();

    public Rs256TokenIssuer(String privateKeyPem, String kid, long lifetimeSeconds) {
        if (privateKeyPem == null || !privateKeyPem.contains("BEGIN PRIVATE KEY")) {
            throw new IllegalArgumentException("JWT_PRIVATE_KEY is not a PKCS#8 PEM private key");
        }
        String base64 = privateKeyPem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        try {
            this.key = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalArgumentException("JWT_PRIVATE_KEY cannot be read", e);
        }
        this.kid = kid;
        this.lifetimeSeconds = lifetimeSeconds;
    }

    @Override
    public IssuedToken issue(User user, Instant now) {
        return sign(user, user.barbershopId(), now, lifetimeSeconds);
    }

    /** The same claims as a login token of that client, plus the barbershop they picked (DEC-AUTH-06). */
    @Override
    public IssuedToken issueBound(User client, UUID barbershopId, Instant now, Duration lifetime) {
        return sign(client, barbershopId, now, lifetime.toSeconds());
    }

    private IssuedToken sign(User user, UUID barbershopId, Instant now, long lifetimeSeconds) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "JWT");
        header.put("kid", kid);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
        claims.put("sub", user.id().toString());
        claims.put("role", user.role().name());
        if (barbershopId != null) {
            claims.put("barbershopId", barbershopId.toString());
        }
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.getEpochSecond() + lifetimeSeconds);
        try {
            String signingInput = b64(json.writeValueAsBytes(header)) + "." + b64(json.writeValueAsBytes(claims));
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(key);
            rsa.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return new IssuedToken(signingInput + "." + b64(rsa.sign()), lifetimeSeconds);
        } catch (Exception e) {
            throw new IllegalStateException("cannot sign the token", e);
        }
    }

    /** The public key as a JSON Web Key (RFC 7517). */
    public Map<String, String> jwk() {
        Map<String, String> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("kid", kid);
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("n", b64(unsigned(key.getModulus())));
        jwk.put("e", b64(unsigned(key.getPublicExponent())));
        return jwk;
    }

    /** The public key as PEM, for services configured with JWT_PUBLIC_KEY. */
    public String publicKeyPem() {
        try {
            var publicKey = KeyFactory.getInstance("RSA").generatePublic(
                    new java.security.spec.RSAPublicKeySpec(key.getModulus(), key.getPublicExponent()));
            return "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(publicKey.getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
