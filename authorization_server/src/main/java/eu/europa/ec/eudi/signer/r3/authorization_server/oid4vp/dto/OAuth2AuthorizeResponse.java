package eu.europa.ec.eudi.signer.r3.authorization_server.oid4vp.dto;

import jakarta.validation.constraints.NotBlank;

public class OAuth2AuthorizeResponse {
    @NotBlank
    private String code;
    private String state;
    // invalid_request | access_denied |
    // unsupported_response_type | invalid_scope |
    // server_error | temporarily_unavailable
    private String error;
    private String error_description;
    private String error_uri;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getError_description() {
        return error_description;
    }

    public void setError_description(String error_description) {
        this.error_description = error_description;
    }

    public String getError_uri() {
        return error_uri;
    }

    public void setError_uri(String error_uri) {
        this.error_uri = error_uri;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "OAuth2AuthorizeResponse{" +
                "code='" + code + '\'' +
                ", state='" + state + '\'' +
                ", error='" + error + '\'' +
                ", error_description='" + error_description + '\'' +
                ", error_uri='" + error_uri + '\'' +
                '}';
    }
}
