package eu.europa.ec.eudi.signer.r3.qtsp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public class AuthConfig {
    private String dbEncryptionPassphrase;
    private String dbEncryptionSalt;

    public String getDbEncryptionPassphrase() {
        return dbEncryptionPassphrase;
    }

    public void setDbEncryptionPassphrase(String dbEncryptionPassphrase) {
        this.dbEncryptionPassphrase = dbEncryptionPassphrase;
    }

    public String getDbEncryptionSalt() {
        return dbEncryptionSalt;
    }

    public void setDbEncryptionSalt(String dbEncryptionSalt) {
        this.dbEncryptionSalt = dbEncryptionSalt;
    }
}
