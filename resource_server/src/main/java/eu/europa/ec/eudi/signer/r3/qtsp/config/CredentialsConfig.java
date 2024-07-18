package eu.europa.ec.eudi.signer.r3.qtsp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "credentials")
public class CredentialsConfig {
    private boolean onlyValidSupport;

    public boolean getOnlyValidSupport() {
        return onlyValidSupport;
    }

    public void setOnlyValidSupport(boolean onlyValidSupport) {
        this.onlyValidSupport = onlyValidSupport;
    }
}
