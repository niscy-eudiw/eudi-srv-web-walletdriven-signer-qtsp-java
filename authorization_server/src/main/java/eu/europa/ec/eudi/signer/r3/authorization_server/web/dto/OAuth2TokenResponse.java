package eu.europa.ec.eudi.signer.r3.authorization_server.web.dto;

import jakarta.validation.constraints.NotBlank;

public class OAuth2TokenResponse {
    @NotBlank
    private String access_token;
    private String refresh_token;
    @NotBlank
    private String token_type;
    private int expires_in;
    private String credentialID;

    public String getAccess_token() {
        return access_token;
    }

    public void setAccess_token(String access_token) {
        this.access_token = access_token;
    }

    public String getRefresh_token() {
        return refresh_token;
    }

    public void setRefresh_token(String refresh_token) {
        this.refresh_token = refresh_token;
    }

    public String getToken_type() {
        return token_type;
    }

    public void setToken_type(String token_type) {
        this.token_type = token_type;
    }

    public int getExpires_in() {
        return expires_in;
    }

    public void setExpires_in(int expires_in) {
        this.expires_in = expires_in;
    }

    public String getCredentialID() {
        return this.credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "OAuth2TokenResponse{" +
                "access_token='" + access_token + '\'' +
                ", refresh_token='" + refresh_token + '\'' +
                ", token_type='" + token_type + '\'' +
                ", expires_in=" + expires_in + '\'' +
                ", credentialID=" + credentialID +
                '}';
    }
}
