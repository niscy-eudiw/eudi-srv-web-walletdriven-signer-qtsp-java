/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.authorization_server.web.dto;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

public class OAuth2AuthorizeRequest {
    @NotBlank
    private String response_type = "code";
    @NotBlank
    private String client_id;
    private String redirect_uri;
    private String scope;
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
        Map<String, String[]> parameters = getParametersFromQueryOrForm(request);
        if (parameters == null)
            throw new IllegalArgumentException("No parameters were received for the OAuth2 /authorize request.");

        authRequest.setResponse_type(getRequiredParameter(parameters, "response_type"));
        authRequest.setClient_id(getRequiredParameter(parameters, "client_id"));
        authRequest.setRedirect_uri(getFirst(parameters, "redirect_uri"));
        authRequest.setScope(getFirst(parameters, "scope"));
        authRequest.setAuthorization_details(getFirst(parameters, "authorization_details"));

        // neither the scope nor the authorization_details are required, if neither is present the scope defaults to "service"
        if (authRequest.getScope() == null && authRequest.getAuthorization_details() == null)
            authRequest.setScope("service");

        authRequest.setCode_challenge(getRequiredParameter(parameters, "code_challenge"));
        authRequest.setCode_challenge_method(getFirst(parameters, "code_challenge_method"));
        authRequest.setState(getFirst(parameters, "state"));
        authRequest.setRequest_uri(getFirst(parameters, "request_uri"));
        authRequest.setLang(getFirst(parameters, "lang"));
        authRequest.setCredentialID(getFirst(parameters, "credentialID"));
        authRequest.setSignatureQualifier(getFirst(parameters, "signatureQualifier"));
        authRequest.setNumSignatures(getFirst(parameters, "numSignatures"));
        authRequest.setHashes(getFirst(parameters, "hashes"));
        authRequest.setHashAlgorithmOID(getFirst(parameters, "hashAlgorithmOID"));
        authRequest.setDescription(getFirst(parameters,"description"));
        authRequest.setAccount_token(getFirst(parameters, "account_token"));
        authRequest.setClientData(getFirst(parameters, "clientData"));
        return authRequest;
    }

    private static Map<String, String[]> getParametersFromQueryOrForm(HttpServletRequest request){
        String query = request.getQueryString();
        if(query == null)
            return request.getParameterMap();

        String[] pares = query.split("&");
        Map<String, String[]> parameters = new HashMap<>();
        for (String pare : pares) {
            String[] nameAndValue = pare.split("=", 2);
            String key = nameAndValue[0];
            String value = nameAndValue[1];
            if(Objects.equals(key, "redirect_uri") || Objects.equals(key, "authorization_details") ||
                  Objects.equals(key, "request_uri") || Objects.equals(key, "credentialID")){
                value = decode(value);
            }

            if(parameters.containsKey(key)){
                String[] oldValues = parameters.get(key);
                String[] newValues = new String[oldValues.length + 1];
                System.arraycopy(oldValues, 0, newValues, 0, oldValues.length); // copy old values
                newValues[oldValues.length] = value;
                parameters.put(key, newValues);
            }
            else parameters.put(key, new String[]{value});
        }
        return parameters;
    }

    private static String decode(String value) {
        return value == null ? null : URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String getFirst(Map<String, String[]> params, String key) {
        if (params == null) return null;
        String[] values = params.get(key);
        if (values == null || values.length == 0) return null;
        return values[0];
    }

    private static String getRequiredParameter(Map<String, String[]> parameters, String name) throws IllegalArgumentException {
        String[] value = parameters.get(name);
        if(value.length != 1){
            throw new IllegalArgumentException("Too many values for the parameter: " + name);
        }
        if (value[0] == null || value[0].isBlank() || !StringUtils.hasText(value[0])) {
            throw new IllegalArgumentException("Missing required parameter: " + name);
        }
        return value[0];
    }

    public static RequestMatcher requestMatcherWithoutScopeOrAuthorizationDetails(){
        return request ->
              request.getParameter("client_id") != null
                    && Objects.equals(request.getParameter("response_type"), "code")
                    && request.getParameter("scope") == null
                    && request.getParameter("authorization_details") == null
                    && request.getParameter("code_challenge") != null;
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
              request.getParameter("client_id") != null &&
                    Objects.equals(request.getParameter("response_type"), "code") &&
                    (
                          (
                                Objects.equals(request.getParameter("scope"), "credential")
                                && (request.getParameter("credentialID") != null || request.getParameter("signatureQualifier") != null)
                                && request.getParameter("hashes") != null
                                && request.getParameter("hashAlgorithmOID") != null
                                && request.getParameter("numSignatures") != null
                          )
                          || request.getParameter("authorization_details") != null
                    )
                    && request.getParameter("code_challenge") != null;
    }
}
