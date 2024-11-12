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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.converter;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2TokenRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

public class TokenRequestConverter implements AuthenticationConverter {

    private final RequestMatcher tokenRequestMatcher;
    private final Logger logger = LogManager.getLogger(TokenRequestConverter.class);

    public TokenRequestConverter(){
        RequestMatcher tokenRequestMatcher = OAuth2TokenRequest.requestMatcher();
        this.tokenRequestMatcher = new AndRequestMatcher(
              new AntPathRequestMatcher(
                    "/oauth2/token", HttpMethod.POST.name()
              ), tokenRequestMatcher
        );
    }

    private OAuth2Error getOAuth2Error(String errorCode, String errorDescription){
        logger.error(errorDescription);
        return new OAuth2Error(errorCode, errorDescription, null);
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        logger.info("Request received at {}", request.getRequestURL().toString());

        if(!this.tokenRequestMatcher.matches(request)){
            if(request.getParameter("client_id") == null){
                logger.error("Missing parameter client_id.");
                throw new OAuth2AuthenticationException(
                      getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter client_id."));
            }
            else if(request.getParameter("grant_type") == null){
                logger.error("Missing parameter grant_type.");
                throw new OAuth2AuthenticationException(
                      getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter client_id."));
            }
            else if(request.getParameter("code") == null){
                logger.error("Missing parameter code.");
                throw new OAuth2AuthenticationException(
                      getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter code."));
            }
        }
        logger.info("Request received match the supported requests.");

        OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.from(request);
        logger.info("Request received: {}", tokenRequest);

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        logger.info("Client Principal present: {}", clientPrincipal);

        // grant_type (REQUIRED)
        String grantType = tokenRequest.getGrant_type();
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
            throw new OAuth2AuthenticationException(
                  getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid parameter grant_type."));
        }
        logger.info("Grant_type ({}) is supported.", grantType);

        // code (REQUIRED)
        String code = tokenRequest.getCode();
        if (!StringUtils.hasText(code) || request.getParameterValues("code").length != 1) {
            throw new OAuth2AuthenticationException(
                  getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter code."));
        }
        logger.info("Code parameter required is present ({}).", code);

        // redirect_uri (REQUIRED)
        String redirectUri = tokenRequest.getRedirect_uri();
        if (StringUtils.hasText(redirectUri) && request.getParameterValues(OAuth2ParameterNames.REDIRECT_URI).length != 1) {
            String errorType = OAuth2ErrorCodes.INVALID_REQUEST;
            String error_description = "The redirect uri parameter is required.";
            throw new OAuth2AuthenticationException(getOAuth2Error(errorType, error_description));
        }
        logger.info("Redirect Uri required is present ({}).", redirectUri);

        Map<String, Object> additionalParameters = getAdditionalParameters(tokenRequest);

        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthenticationToken =
              new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri, additionalParameters);

        logger.info("OAuth2AuthorizationCodeAuthenticationToken is generated.");
        return authorizationCodeAuthenticationToken;
    }

    private static @NotNull Map<String, Object> getAdditionalParameters(OAuth2TokenRequest tokenRequest) {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("refresh_token", tokenRequest.getRefresh_token());
        additionalParameters.put("client_id", tokenRequest.getClient_id());
        additionalParameters.put("client_secret", tokenRequest.getClient_secret());
        additionalParameters.put("code_verifier", tokenRequest.getCode_verifier());
        additionalParameters.put("client_assertion", tokenRequest.getClient_assertion());
        additionalParameters.put("client_assertion_type", tokenRequest.getClient_assertion_type());
        additionalParameters.put("authorization_details", tokenRequest.getAuthorization_details());
        additionalParameters.put("clientData", tokenRequest.getClientData());
        return additionalParameters;
    }
}
