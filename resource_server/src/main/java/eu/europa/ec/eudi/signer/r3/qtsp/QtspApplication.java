package eu.europa.ec.eudi.signer.r3.qtsp;

import eu.europa.ec.eudi.signer.r3.qtsp.config.InfoProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({ InfoProperties.class })
public class QtspApplication {

	public static void main(String[] args) {
		SpringApplication.run(QtspApplication.class, args);
	}



}
