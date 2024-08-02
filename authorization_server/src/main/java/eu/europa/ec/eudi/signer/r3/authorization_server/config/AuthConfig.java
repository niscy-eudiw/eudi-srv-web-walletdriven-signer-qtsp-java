package eu.europa.ec.eudi.signer.r3.authorization_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public class AuthConfig {
    private String datasourceUsername;
    private String datasourcePassword;
    private String jwtTokenSecret;
    private String sadTokenSecret;
    private String dbEncryptionPassphrase;
    private String dbEncryptionSalt;

    public String getDatasourceUsername() {
        return this.datasourceUsername;
    }

    public void setDatasourceUsername(String datasourceUsername) {
        this.datasourceUsername = datasourceUsername;
    }

    public String getDatasourcePassword() {
        return this.datasourcePassword;
    }

    public void setDatasourcePassword(String datasourcePassword) {
        this.datasourcePassword = datasourcePassword;
    }

    public String getJwtTokenSecret() {
        return this.jwtTokenSecret;
    }

    public void setJwtTokenSecret(String jwtTokenSecret) {
        this.jwtTokenSecret = jwtTokenSecret;
    }

    public String getSadTokenSecret() {
        return this.sadTokenSecret;
    }

    public void setSadTokenSecret(String sadTokenSecret) {
        this.sadTokenSecret = sadTokenSecret;
    }

    public String getDbEncryptionPassphrase() {
        return this.dbEncryptionPassphrase;
    }

    public void setDbEncryptionPassphrase(String dbEncryptionPassphrase) {
        this.dbEncryptionPassphrase = dbEncryptionPassphrase;
    }

    public String getDbEncryptionSalt() {
        return this.dbEncryptionSalt;
    }

    public void setDbEncryptionSalt(String dbEncryptionSalt) {
        this.dbEncryptionSalt = dbEncryptionSalt;
    }

}