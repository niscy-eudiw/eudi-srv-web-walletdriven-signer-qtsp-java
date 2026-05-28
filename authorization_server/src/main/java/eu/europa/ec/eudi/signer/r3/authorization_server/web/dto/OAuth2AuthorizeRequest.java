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

import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2ScopesNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2AuthorizationDetailsNames;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
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

    public static OAuth2AuthorizeRequest from(HttpServletRequest request) throws IllegalArgumentException {
        OAuth2AuthorizeRequest authRequest = new OAuth2AuthorizeRequest();
        Map<String, String[]> parameters = request.getParameterMap();
        if (parameters == null)
            throw new IllegalArgumentException("No parameters were received for the OAuth2 /authorize request.");

        authRequest.setResponse_type(getRequiredParameter(parameters, OAuth2ParameterNames.RESPONSE_TYPE));
        authRequest.setClient_id(getRequiredParameter(parameters, OAuth2ParameterNames.CLIENT_ID));
        authRequest.setRedirect_uri(getFirst(parameters, OAuth2ParameterNames.REDIRECT_URI));
        authRequest.setState(getFirst(parameters, OAuth2ParameterNames.STATE));
        authRequest.setScope(getFirst(parameters, OAuth2ParameterNames.SCOPE));
        authRequest.setAuthorization_details(getFirst(parameters, OAuth2CustomParameterNames.AUTHORIZATION_DETAILS));

        // Resolve scope from authorization_details type when no explicit scope
        // provided.
        // Per spec: lang SHALL NOT be used if authorization_details is present.
        if (authRequest.getAuthorization_details() != null) {
            authRequest.setScope(resolveScopeFromAuthorizationDetails(authRequest.getAuthorization_details()));
            // lang is ignored when authorization_details is present
        } else if (authRequest.getScope() == null) {
            // Neither scope nor authorization_details present — default to service
            authRequest.setScope(OAuth2ScopesNames.SERVICE);
            authRequest.setLang(getFirst(parameters, OAuth2CustomParameterNames.LANG));
        } else {
            authRequest.setLang(getFirst(parameters, OAuth2CustomParameterNames.LANG));
        }

        authRequest.setCode_challenge(getRequiredParameter(parameters, PkceParameterNames.CODE_CHALLENGE));
        authRequest.setCode_challenge_method(getFirst(parameters, PkceParameterNames.CODE_CHALLENGE_METHOD));
        authRequest.setRequest_uri(getFirst(parameters, OAuth2CustomParameterNames.REQUEST_URI));
        authRequest.setCredentialID(getFirst(parameters, OAuth2CustomParameterNames.CREDENTIAL_ID));
        authRequest.setSignatureQualifier(getFirst(parameters, OAuth2CustomParameterNames.SIGNATURE_QUALIFIER));
        authRequest.setNumSignatures(getFirst(parameters, OAuth2CustomParameterNames.NUM_SIGNATURES));
        authRequest.setHashes(getFirst(parameters, OAuth2CustomParameterNames.HASHES));
        authRequest.setHashAlgorithmOID(getFirst(parameters, OAuth2CustomParameterNames.HASH_ALGORITHM_OID));
        authRequest.setDescription(getFirst(parameters, OAuth2CustomParameterNames.DESCRIPTION));
        authRequest.setAccount_token(getFirst(parameters, OAuth2CustomParameterNames.ACCOUNT_TOKEN));
        authRequest.setClientData(getFirst(parameters, OAuth2CustomParameterNames.CLIENT_DATA));
        return authRequest;
    }

    /**
     * Derives the OAuth2 scope from the 'type' field inside authorization_details.
     * Falls back to CREDENTIAL scope if the type is unrecognised.
     */
    private static String resolveScopeFromAuthorizationDetails(String authorizationDetails) {
        try {
            JSONArray arr = new JSONArray(authorizationDetails);
            if (!arr.isEmpty()) {
                JSONObject first = arr.getJSONObject(0);
                if (first.has(OAuth2AuthorizationDetailsNames.TYPE)) {
                    String type = first.getString(OAuth2AuthorizationDetailsNames.TYPE);
                    if(OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_CREATION.contains(type)){
                        return OAuth2ScopesNames.CREDENTIAL_CREATION;
                    }
                    else if (OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_DELETE.contains(type)){
                        return OAuth2ScopesNames.CREDENTIAL_DELETION;
                    }
                    else {
                        return OAuth2ScopesNames.CREDENTIAL;
                    }
                }
            }
        } catch (Exception ignored) {
            // malformed authorization_details — let validation catch it downstream
        }
        return OAuth2ScopesNames.CREDENTIAL;
    }

    private static String getFirst(Map<String, String[]> params, String key) {
        if (params == null)
            return null;
        String[] values = params.get(key);
        if (values == null || values.length == 0)
            return null;
        return values[0];
    }

    private static String getRequiredParameter(Map<String, String[]> parameters, String name)
            throws IllegalArgumentException {
        String[] value = parameters.get(name);
        if (value.length != 1) {
            throw new IllegalArgumentException("Too many values for the parameter: " + name);
        }
        if (value[0] == null || value[0].isBlank() || !StringUtils.hasText(value[0])) {
            throw new IllegalArgumentException("Missing required parameter: " + name);
        }
        return value[0];
    }

    public static RequestMatcher requestMatcherWithoutScopeOrAuthorizationDetails() {
        return request -> request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null
                && Objects.equals(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE),
                        OAuth2AuthorizationResponseType.CODE.getValue())
                && request.getParameter(OAuth2ParameterNames.SCOPE) == null
                && request.getParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS) == null
                && request.getParameter(PkceParameterNames.CODE_CHALLENGE) != null;
    }

    public static RequestMatcher requestMatcherForService() {
        return request -> request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null
                && Objects.equals(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE),
                        OAuth2AuthorizationResponseType.CODE.getValue())
                && Objects.equals(request.getParameter(OAuth2ParameterNames.SCOPE), OAuth2ScopesNames.SERVICE)
                && request.getParameter(PkceParameterNames.CODE_CHALLENGE) != null;
    }

    public static RequestMatcher requestMatcherForCredential() {
        return request -> request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null &&
                Objects.equals(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE),
                        OAuth2AuthorizationResponseType.CODE.getValue())
                &&
                ((Objects.equals(request.getParameter(OAuth2ParameterNames.SCOPE), OAuth2ScopesNames.CREDENTIAL)
                        && (request.getParameter(OAuth2CustomParameterNames.CREDENTIAL_ID) != null
                                || request.getParameter(OAuth2CustomParameterNames.SIGNATURE_QUALIFIER) != null)
                        && request.getParameter(OAuth2CustomParameterNames.HASHES) != null
                        && request.getParameter(OAuth2CustomParameterNames.HASH_ALGORITHM_OID) != null
                        && request.getParameter(OAuth2CustomParameterNames.NUM_SIGNATURES) != null)
                        || (request.getParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS) != null
                                && isAuthorizationDetailsOfType(
                                        request.getParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS),
                                        OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL)))
                && request.getParameter(PkceParameterNames.CODE_CHALLENGE) != null;
    }

    // New: matcher for credential-creation scope (1.1.2)
    public static RequestMatcher requestMatcherForCredentialCreation() {
        return request -> request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null
                && Objects.equals(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE),
                        OAuth2AuthorizationResponseType.CODE.getValue())
                && request.getParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS) != null
                && isAuthorizationDetailsOfType(request.getParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS),
                        OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_CREATION)
                && request.getParameter(PkceParameterNames.CODE_CHALLENGE) != null;
    }

    // New: matcher for credential-delete scope (1.1.3)
    public static RequestMatcher requestMatcherForCredentialDelete() {
        return request -> request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null
                && Objects.equals(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE),
                        OAuth2AuthorizationResponseType.CODE.getValue())
                && request.getParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS) != null
                && isAuthorizationDetailsOfType(request.getParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS),
                        OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_DELETE)
                && request.getParameter(PkceParameterNames.CODE_CHALLENGE) != null;
    }

    /**
     * Returns true if the first element of the authorization_details JSON array has
     * the given type value.
     */
    private static boolean isAuthorizationDetailsOfType(String authorizationDetails, List<String> expectedType) {
        try {
            JSONArray arr = new JSONArray(authorizationDetails);
            if (!arr.isEmpty()) {
                JSONObject first = arr.getJSONObject(0);
                return expectedType.contains(first.optString(OAuth2AuthorizationDetailsNames.TYPE));
            }
        } catch (Exception ignored) {
        }
        return false;
    }
}
