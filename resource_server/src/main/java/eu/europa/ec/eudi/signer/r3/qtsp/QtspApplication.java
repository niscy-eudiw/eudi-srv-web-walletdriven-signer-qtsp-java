package eu.europa.ec.eudi.signer.r3.qtsp;

import eu.europa.ec.eudi.signer.r3.qtsp.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.qtsp.config.CredentialsConfig;
import eu.europa.ec.eudi.signer.r3.qtsp.config.InfoConfig;
import eu.europa.ec.eudi.signer.r3.qtsp.config.TrustedIssuersCertificateConfig;
import eu.europa.ec.eudi.signer.r3.qtsp.model.certificates.ejbca.EjbcaProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({ InfoConfig.class, EjbcaProperties.class,
	TrustedIssuersCertificateConfig.class, AuthConfig.class, CredentialsConfig.class })
public class QtspApplication {

	public static void main(String[] args) {
		SpringApplication.run(QtspApplication.class, args);
	}

}
