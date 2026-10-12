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
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.util.OAuth2ValidationUtils;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
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

/**
 * Attempts to extract an Access Token Request from HttpServletRequest for the
 * OAuth 2.0 Authorization Code Grant and then converts it to an
 * OAuth2AuthorizationCodeAuthenticationToken used for authenticating the
 * authorization grant.
 **/
public class TokenRequestConverter implements AuthenticationConverter {

    private final RequestMatcher tokenRequestMatcher;
    private final Logger logger = LoggerFactory.getLogger(TokenRequestConverter.class);

    public TokenRequestConverter(){
        RequestMatcher tokenRequestMatcher = OAuth2TokenRequest.requestMatcher();
        this.tokenRequestMatcher = new AndRequestMatcher(
              new AntPathRequestMatcher(
                    "/oauth2/token", HttpMethod.POST.name()
              ), tokenRequestMatcher
        );
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        logger.info("Request received at {}", request.getRequestURL().toString());

        if(!this.tokenRequestMatcher.matches(request)){
            if(request.getParameter(OAuth2ParameterNames.GRANT_TYPE) == null){
                throw new OAuth2AuthenticationException(
                      OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter 'grant_type'."));
            }
            else if(!request.getParameter(OAuth2ParameterNames.GRANT_TYPE).equals(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())){
                throw new OAuth2AuthenticationException(
                      OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "Invalid parameter 'grant_type'."));
            }
            else if(request.getParameter(OAuth2ParameterNames.CLIENT_ID) == null){
                throw new OAuth2AuthenticationException(
                      OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter 'client_id'."));
            }
            else if(!StringUtils.hasText(request.getParameter(OAuth2ParameterNames.CODE)) ||
                  request.getParameterValues(OAuth2ParameterNames.CODE).length != 1){
                throw new OAuth2AuthenticationException(
                      OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter 'code'."));
            }
            else if(StringUtils.hasText(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)) &&
                  request.getParameterValues(OAuth2ParameterNames.REDIRECT_URI).length != 1){
                throw new OAuth2AuthenticationException(
                      OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "Parameter 'redirect_uri' if present in the request should be unique."));
            }
        }
        logger.info("Request received match the supported requests.");

        OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.from(request);
        logger.info("Request received: {}", tokenRequest);

        Map<String, Object> additionalParameters = getAdditionalParameters(tokenRequest);

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        logger.info("Client Authentication: {}", clientPrincipal);

        OAuth2AuthorizationCodeAuthenticationToken oauth2TokenRequest = new OAuth2AuthorizationCodeAuthenticationToken(
              tokenRequest.getCode(),
              clientPrincipal,
              tokenRequest.getRedirect_uri(),
              additionalParameters);
        logger.info("OAuth2AuthorizationCodeAuthenticationToken is generated.");
        return oauth2TokenRequest;
    }

    private static @NotNull Map<String, Object> getAdditionalParameters(OAuth2TokenRequest tokenRequest) {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2TokenType.REFRESH_TOKEN.getValue(), tokenRequest.getRefresh_token());
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, tokenRequest.getClient_id());
        additionalParameters.put(OAuth2ParameterNames.CLIENT_SECRET, tokenRequest.getClient_secret());
        additionalParameters.put(PkceParameterNames.CODE_VERIFIER, tokenRequest.getCode_verifier());
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ASSERTION, tokenRequest.getClient_assertion());
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, tokenRequest.getClient_assertion_type());
        additionalParameters.put(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, tokenRequest.getAuthorization_details());
        additionalParameters.put(OAuth2CustomParameterNames.CLIENT_DATA, tokenRequest.getClientData());
        return additionalParameters;
    }
}
