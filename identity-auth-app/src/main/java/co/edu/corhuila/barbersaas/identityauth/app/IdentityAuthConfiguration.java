package co.edu.corhuila.barbersaas.identityauth.app;

import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.AuthFilter;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.CorrelationFilter;
import co.edu.corhuila.barbersaas.identityauth.adapter.in.http.Rs256Verifier;
import co.edu.corhuila.barbersaas.identityauth.adapter.out.persistence.InMemoryUserRepository;
import co.edu.corhuila.barbersaas.identityauth.adapter.out.persistence.JdbcUserRepository;
import co.edu.corhuila.barbersaas.identityauth.adapter.out.persistence.UuidGenerator;
import co.edu.corhuila.barbersaas.identityauth.adapter.out.security.BCryptPasswordHasher;
import co.edu.corhuila.barbersaas.identityauth.adapter.out.security.OpaqueRefreshTokens;
import co.edu.corhuila.barbersaas.identityauth.adapter.out.security.Rs256TokenIssuer;
import co.edu.corhuila.barbersaas.identityauth.application.port.in.AuthUseCases;
import co.edu.corhuila.barbersaas.identityauth.application.port.out.UserRepository;
import co.edu.corhuila.barbersaas.identityauth.application.usecase.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Composition root: the only place that knows every concrete type. The pool and its limits are
 * built here explicitly (norm 5.3.10), so they are read in code review instead of hidden in defaults.
 */
@Configuration
public class IdentityAuthConfiguration {

    /** The JDBC access, or none when DATABASE_URL is empty (in-memory repository, no database needed). */
    record Database(JdbcTemplate jdbc) {
        Optional<JdbcTemplate> template() {
            return Optional.ofNullable(jdbc);
        }
    }

    @Bean
    Database database(@Value("${identity-auth.database.url:}") String url,
                                @Value("${identity-auth.database.user:}") String user,
                                @Value("${identity-auth.database.password:}") String password,
                                @Value("${identity-auth.database.pool-max:10}") int poolMax,
                                @Value("${identity-auth.database.statement-timeout-ms:5000}") int statementTimeoutMs) {
        if (url.isBlank()) {
            return new Database(null);
        }
        HikariConfig pool = new HikariConfig();
        pool.setJdbcUrl(url);
        pool.setUsername(user);                                       // identity_auth_app, never the administrator
        pool.setPassword(password);
        pool.setMaximumPoolSize(poolMax);
        pool.setConnectionTimeout(Duration.ofSeconds(5).toMillis());
        pool.setMaxLifetime(Duration.ofMinutes(30).toMillis());
        pool.setConnectionInitSql("SET statement_timeout = " + statementTimeoutMs);
        return new Database(new JdbcTemplate(new HikariDataSource(pool)));
    }

    @Bean
    UserRepository userRepository(Database database) {
        return database.template().<UserRepository>map(t -> new JdbcUserRepository(t,
                        new org.springframework.transaction.support.TransactionTemplate(
                                new org.springframework.jdbc.datasource.DataSourceTransactionManager(t.getDataSource()))))
                .orElseGet(InMemoryUserRepository::new);
    }

    /** JWT_PRIVATE_KEY: the PEM itself; a one-line value with literal \n escapes, as an env file holds it, is accepted. */
    @Bean
    Rs256TokenIssuer tokenIssuer(@Value("${JWT_PRIVATE_KEY:}") String pem,
                                 @Value("${JWT_KID:dev-1}") String kid,
                                 @Value("${JWT_LIFETIME_SECONDS:86400}") long lifetimeSeconds) {
        return new Rs256TokenIssuer(pem.replace("\\n", "\n"), kid, lifetimeSeconds);
    }

    @Bean
    AuthUseCases authUseCases(UserRepository users, Rs256TokenIssuer issuer, Database database,
                              @Value("${BCRYPT_STRENGTH:10}") int strength) {
        return new AuthService(users, new BCryptPasswordHasher(strength), issuer,
                new OpaqueRefreshTokens(database.jdbc()), new UuidGenerator(), Clock.systemUTC());
    }

    @Bean
    Rs256Verifier tokenVerifier(Rs256TokenIssuer issuer) {
        return new Rs256Verifier(issuer.publicKeyPem());
    }

    @Bean
    FilterRegistrationBean<CorrelationFilter> correlationFilter() {
        FilterRegistrationBean<CorrelationFilter> bean = new FilterRegistrationBean<>(new CorrelationFilter());
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }

    @Bean
    FilterRegistrationBean<AuthFilter> authFilter(Rs256Verifier verifier, ObjectMapper json) {
        FilterRegistrationBean<AuthFilter> bean = new FilterRegistrationBean<>(new AuthFilter(verifier, json));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return bean;
    }
}
