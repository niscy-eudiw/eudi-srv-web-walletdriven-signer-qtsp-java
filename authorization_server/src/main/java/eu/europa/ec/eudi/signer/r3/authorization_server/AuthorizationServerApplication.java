package eu.europa.ec.eudi.signer.r3.authorization_server;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.TrustedIssuersCertificateConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.VerifierConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({ TrustedIssuersCertificateConfig.class, VerifierConfig.class, AuthConfig.class })
public class AuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

}