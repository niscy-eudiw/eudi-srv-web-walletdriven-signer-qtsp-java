package eu.europa.ec.eudi.signer.r3.common_tools.utils;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableAutoConfiguration
@ConfigurationProperties(prefix = "application-crypto")
public class CryptoProperties {
	private String symmetricSecretKey;

	public String getSymmetricSecretKey() {
		return symmetricSecretKey;
	}

	public void setSymmetricSecretKey(String symmetricSecretKey) {
		this.symmetricSecretKey = symmetricSecretKey;
	}
}