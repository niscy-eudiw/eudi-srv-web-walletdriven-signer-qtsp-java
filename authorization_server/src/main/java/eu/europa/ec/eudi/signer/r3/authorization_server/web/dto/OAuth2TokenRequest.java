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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import java.util.Objects;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

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
              Objects.equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE), AuthorizationGrantType.AUTHORIZATION_CODE.getValue()) && // Grant type should be 'authorization_code'
              StringUtils.hasText(request.getParameter(OAuth2ParameterNames.CODE)) && request.getParameterValues(OAuth2ParameterNames.CODE).length == 1 &&
              request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null &&
              (!StringUtils.hasText(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)) || request.getParameterValues(OAuth2ParameterNames.REDIRECT_URI).length == 1);
    }

    public static OAuth2TokenRequest from(HttpServletRequest request) throws IllegalArgumentException{
        OAuth2TokenRequest oauthRequest = new OAuth2TokenRequest();
        oauthRequest.setGrant_type(request.getParameter(OAuth2ParameterNames.GRANT_TYPE));
        oauthRequest.setCode(request.getParameter(OAuth2ParameterNames.CODE));
        oauthRequest.setRefresh_token(request.getParameter(OAuth2TokenType.REFRESH_TOKEN.getValue()));
        oauthRequest.setClient_id(request.getParameter(OAuth2ParameterNames.CLIENT_ID));
        oauthRequest.setClient_secret(request.getParameter(OAuth2ParameterNames.CLIENT_SECRET));
        oauthRequest.setCode_verifier(request.getParameter(PkceParameterNames.CODE_VERIFIER));
        oauthRequest.setClient_assertion(request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION));
        oauthRequest.setClient_assertion_type(request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE));
        oauthRequest.setRedirect_uri(request.getParameter(OAuth2ParameterNames.REDIRECT_URI));
        oauthRequest.setAuthorization_details(request.getParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS));
        oauthRequest.setClientData(request.getParameter(OAuth2CustomParameterNames.CLIENT_DATA));
        return oauthRequest;
    }

}
