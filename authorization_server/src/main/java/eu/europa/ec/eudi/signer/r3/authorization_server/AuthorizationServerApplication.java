package eu.europa.ec.eudi.signer.r3.authorization_server;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({ TrustedIssuersCertificateConfig.class, VerifierConfig.class, AuthConfig.class, OAuth2ClientRegistrationConfig.class })
public class AuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

}