package co.edu.corhuila.barbersaas.identityauth.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "co.edu.corhuila.barbersaas.identityauth")
public class IdentityAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(IdentityAuthApplication.class, args);
    }
}
