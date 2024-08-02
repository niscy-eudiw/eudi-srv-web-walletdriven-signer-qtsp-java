package eu.europa.ec.eudi.signer.r3.resource_server;

import eu.europa.ec.eudi.signer.r3.resource_server.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.config.CredentialsConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.config.InfoConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({ InfoConfig.class, EjbcaProperties.class, AuthConfig.class, CredentialsConfig.class })
public class QtspApplication {

	public static void main(String[] args) {
		SpringApplication.run(QtspApplication.class, args);
	}

}
