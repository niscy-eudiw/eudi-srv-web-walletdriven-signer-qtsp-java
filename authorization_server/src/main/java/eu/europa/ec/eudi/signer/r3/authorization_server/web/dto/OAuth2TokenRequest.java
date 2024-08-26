package eu.europa.ec.eudi.signer.r3.authorization_server.web.dto;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Objects;

public class OAuth2TokenRequest {
    // authorization_code | client_credentials | refresh_token
    @NotBlank
    private String grant_type;
    private String code;
    private String refresh_token;
    @NotBlank
    private String client_id;
    private String client_secret;
    private String code_verifier;
    private String client_assertion;
    private String client_assertion_type;
    private String redirect_uri;
    private String authorization_details;
    private String clientData;

    public String getGrant_type() {
        return grant_type;
    }

    public void setGrant_type(String grant_type) {
        this.grant_type = grant_type;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getRefresh_token() {
        return refresh_token;
    }

    public void setRefresh_token(String refresh_token) {
        this.refresh_token = refresh_token;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public String getClient_secret() {
        return client_secret;
    }

    public void setClient_secret(String client_secret) {
        this.client_secret = client_secret;
    }

    public String getClient_assertion() {
        return client_assertion;
    }

    public void setClient_assertion(String client_assertion) {
        this.client_assertion = client_assertion;
    }

    public String getClient_assertion_type() {
        return client_assertion_type;
    }

    public void setClient_assertion_type(String client_assertion_type) {
        this.client_assertion_type = client_assertion_type;
    }

    public String getRedirect_uri() {
        return redirect_uri;
    }

    public void setRedirect_uri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }

    public String getAuthorization_details() {
        return authorization_details;
    }

    public void setAuthorization_details(String authorization_details) {
        this.authorization_details = authorization_details;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    public String getCode_verifier() {
        return code_verifier;
    }

    public void setCode_verifier(String code_verifier) {
        this.code_verifier = code_verifier;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "OAuth2TokenRequestDTO{" +
                "grant_type='" + grant_type + '\'' +
                ", code='" + code + '\'' +
                ", refresh_token='" + refresh_token + '\'' +
                ", client_id='" + client_id + '\'' +
                ", client_secret='" + client_secret + '\'' +
                ", client_assertion='" + client_assertion + '\'' +
                ", client_assertion_type='" + client_assertion_type + '\'' +
                ", redirect_uri='" + redirect_uri + '\'' +
                ", authorization_details='" + authorization_details + '\'' +
                ", clientData='" + clientData + '\'' +
                '}';
    }

    public static RequestMatcher requestMatcher(){
        return request ->
              request.getParameter("grant_type") != null &&
              (!Objects.equals(request.getParameter("grant_type"), "authorization_code") || request.getParameter("code") != null) &&
              request.getParameter("client_id") != null;
    }

    public static OAuth2TokenRequest from(HttpServletRequest request) throws IllegalArgumentException{
        OAuth2TokenRequest oauthRequest = new OAuth2TokenRequest();
        oauthRequest.setGrant_type(request.getParameter("grant_type"));
        oauthRequest.setCode(request.getParameter("code"));
        oauthRequest.setRefresh_token(request.getParameter("refresh_token"));
        oauthRequest.setClient_id(request.getParameter("client_id"));
        oauthRequest.setClient_secret(request.getParameter("client_secret"));
        oauthRequest.setCode_verifier(request.getParameter("code_verifier"));
        oauthRequest.setClient_assertion(request.getParameter("client_assertion"));
        oauthRequest.setClient_assertion_type(request.getParameter("client_assertion_type"));
        oauthRequest.setRedirect_uri(request.getParameter("redirect_uri"));
        oauthRequest.setAuthorization_details(request.getParameter("authorization_details"));
        oauthRequest.setClientData(request.getParameter("clientData"));
        return oauthRequest;
    }

}
