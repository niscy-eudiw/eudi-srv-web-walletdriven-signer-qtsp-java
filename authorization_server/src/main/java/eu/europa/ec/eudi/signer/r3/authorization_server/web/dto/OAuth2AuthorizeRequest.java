package eu.europa.ec.eudi.signer.r3.authorization_server.web.dto;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.Objects;

public class OAuth2AuthorizeRequest {
    @NotBlank
    private String response_type = "code";
    @NotBlank
    private String client_id;
    private String redirect_uri;
    private String scope = "service";

    /*
     * Authorization_details:
     * * type
     * * credentialID
     * * signatureQualifier
     * * documentDigests
     * * hashAlgorithmOID
     * * locations
     */
    private String authorization_details;
    @NotBlank
    private String code_challenge;
    private String code_challenge_method = "plain";
    private String state;
    private String request_uri;

    private String lang;

    private String credentialID;
    private String signatureQualifier;
    private String numSignatures;
    private String hashes;
    private String hashAlgorithmOID;

    private String description;
    private String account_token;
    private String clientData;

    public String getResponse_type() {
        return response_type;
    }

    public void setResponse_type(String response_type) {
        this.response_type = response_type;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public String getRedirect_uri() {
        return redirect_uri;
    }

    public void setRedirect_uri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getAuthorization_details() {
        return authorization_details;
    }

    public void setAuthorization_details(String authorization_details) {
        this.authorization_details = authorization_details;
    }

    public String getCode_challenge() {
        return code_challenge;
    }

    public void setCode_challenge(String code_challenge) {
        this.code_challenge = code_challenge;
    }

    public String getCode_challenge_method() {
        return code_challenge_method;
    }

    public void setCode_challenge_method(String code_challenge_method) {
        this.code_challenge_method = code_challenge_method;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getRequest_uri() {
        return request_uri;
    }

    public void setRequest_uri(String request_uri) {
        this.request_uri = request_uri;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getSignatureQualifier() {
        return signatureQualifier;
    }

    public void setSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
    }

    public String getNumSignatures() {
        return numSignatures;
    }

    public void setNumSignatures(String numSignatures) {
        this.numSignatures = numSignatures;
    }

    public String getHashes() {
        return hashes;
    }

    public void setHashes(String hashes) {
        this.hashes = hashes;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getAccount_token() {
        return account_token;
    }

    public void setAccount_token(String account_token) {
        this.account_token = account_token;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "OAuth2AuthorizeRequestDTO{" +
                "response_type='" + response_type + '\'' +
                ", client_id='" + client_id + '\'' +
                ", redirect_uri='" + redirect_uri + '\'' +
                ", scope='" + scope + '\'' +
                ", authorization_details='" + authorization_details + '\'' +
                ", code_challenge='" + code_challenge + '\'' +
                ", code_challenge_method='" + code_challenge_method + '\'' +
                ", state='" + state + '\'' +
                ", request_uri='" + request_uri + '\'' +
                ", lang='" + lang + '\'' +
                ", credentialID='" + credentialID + '\'' +
                ", signatureQualifier='" + signatureQualifier + '\'' +
                ", numSignatures='" + numSignatures + '\'' +
                ", hashes='" + hashes + '\'' +
                ", hashAlgorithmOID='" + hashAlgorithmOID + '\'' +
                ", description='" + description + '\'' +
                ", account_token='" + account_token + '\'' +
                ", clientData='" + clientData + '\'' +
                '}';
    }

    public static OAuth2AuthorizeRequest from(HttpServletRequest request) throws IllegalArgumentException{
        OAuth2AuthorizeRequest authRequest = new OAuth2AuthorizeRequest();

        authRequest.setResponse_type(getRequiredParameter(request, "response_type"));
        authRequest.setClient_id(getRequiredParameter(request, "client_id"));
        authRequest.setRedirect_uri(request.getParameter("redirect_uri"));
        authRequest.setScope(request.getParameter("scope"));
        authRequest.setAuthorization_details(request.getParameter("authorization_details"));
        authRequest.setCode_challenge(getRequiredParameter(request, "code_challenge"));
        authRequest.setCode_challenge_method(request.getParameter("code_challenge_method"));
        authRequest.setState(request.getParameter("state"));
        authRequest.setRequest_uri(request.getParameter("request_uri"));
        authRequest.setLang(request.getParameter("lang"));
        authRequest.setCredentialID(request.getParameter("credentialID"));
        authRequest.setSignatureQualifier(request.getParameter("signatureQualifier"));
        authRequest.setNumSignatures(request.getParameter("numSignatures"));
        authRequest.setHashes(request.getParameter("hashes"));
        authRequest.setHashAlgorithmOID(request.getParameter("hashAlgorithmOID"));
        authRequest.setDescription(request.getParameter("description"));
        authRequest.setAccount_token(request.getParameter("account_token"));
        authRequest.setClientData(request.getParameter("clientData"));

        return authRequest;
    }

    private static String getRequiredParameter(HttpServletRequest request, String name) throws IllegalArgumentException {
        String value = request.getParameter(name);
        if (value == null || value.isBlank() || !StringUtils.hasText(value)) {
            throw new IllegalArgumentException("Missing required parameter: " + name);
        }
        if(request.getParameterValues(name).length != 1){
            throw new IllegalArgumentException("Too many values for the parameter: " + name);
        }
        return value;
    }

    public static RequestMatcher requestMatcherForService(){
        return request ->
              request.getParameter("client_id") != null
              && Objects.equals(request.getParameter("response_type"), "code")
              && Objects.equals(request.getParameter("scope"), "service")
              && request.getParameter("code_challenge") != null;
    }

    public static RequestMatcher requestMatcherForCredential(){
        return request ->
              request.getParameter("client_id") != null
              && Objects.equals(request.getParameter("response_type"), "code")
              && Objects.equals(request.getParameter("scope"), "credential")
              && request.getParameter("code_challenge") != null
              && (request.getParameter("credentialID") != null
                    || request.getParameter("signatureQualifier") != null)
              && request.getParameter("numSignatures") != null
              && request.getParameter("hashes") != null;
    }
}
