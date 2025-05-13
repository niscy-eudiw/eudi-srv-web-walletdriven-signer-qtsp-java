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

import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin.UsernamePasswordAuthenticationTokenExtended;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.OID4VPAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * A Pre-processor used when attempting to extract an OAuth2 Authorization Request
 * from a HttpServletRequest to an instance of OAuth2AuthorizationCodeRequestAuthenticationToken.
 */
public class AuthorizationCodeRequestConverter implements AuthenticationConverter {
    private final RequestMatcher authenticationServiceRequestMatcher;
    private final RequestMatcher authorizationCredentialRequestMatcher;
    private final RequestMatcher withoutScopeOrAuthorizationDetailsRequestMatcher;
    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
          "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final Logger logger = LogManager.getLogger(AuthorizationCodeRequestConverter.class);

    public AuthorizationCodeRequestConverter(){
        RequestMatcher serviceRequestMatcher = OAuth2AuthorizeRequest.requestMatcherForService();
        this.authenticationServiceRequestMatcher = new AndRequestMatcher(
            new AntPathRequestMatcher(
                "/oauth2/authorize", HttpMethod.GET.name()
            ), serviceRequestMatcher
        );

        RequestMatcher credentialsRequestMatcher = OAuth2AuthorizeRequest.requestMatcherForCredential();
        this.authorizationCredentialRequestMatcher = new AndRequestMatcher(
            new AntPathRequestMatcher(
                "/oauth2/authorize", HttpMethod.GET.name()
            ), credentialsRequestMatcher
        );

        // neither the scope nor the authorization_details are required, if neither is present the scope defaults to "service"
        RequestMatcher withoutScopeOrAuthorizationDetails = OAuth2AuthorizeRequest.requestMatcherWithoutScopeOrAuthorizationDetails();
        this.withoutScopeOrAuthorizationDetailsRequestMatcher = new AndRequestMatcher(
              new AntPathRequestMatcher(
                    "/oauth2/authorize", HttpMethod.GET.name()
              ), withoutScopeOrAuthorizationDetails
        );
    }

    @Override
    public Authentication convert(HttpServletRequest request){
        logger.info("Request received at {}", request.getRequestURL().toString());
        logger.info(request.getQueryString());

        if (!this.authenticationServiceRequestMatcher.matches(request) &&
              !this.authorizationCredentialRequestMatcher.matches(request) &&
              !this.withoutScopeOrAuthorizationDetailsRequestMatcher.matches(request))
        {
            if (!request.getParameter("response_type").equals("code")) {
                String error_description = "The response type in the request is not supported.";
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, error_description, null);
                logger.error(error.toString());
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
            } else {
                String error_description = "The request is missing a required parameter.";
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, error_description, null);
                logger.error(error.toString());
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
            }
        }
        logger.info("Request received match the supported requests.");

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(request);
        logger.info("Request received: {}", authorizeRequest);

        Map<String, Object> additionalParameters = getAdditionalParameters(authorizeRequest);
        Set<String> scopes = new HashSet<>();
        if(authorizeRequest.getScope() == null && authorizeRequest.getAuthorization_details() != null)
            scopes.add("credential");
        else scopes.add(authorizeRequest.getScope());

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            logger.warn("Authentication is not present. The user is not authenticated.");
            principal = ANONYMOUS_AUTHENTICATION;
        }
        else if (!isSupportedAuthentication(principal)) {
            logger.warn("Authentication present is not valid. The authentication mechanism is not the supported.");
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }
        else if(principal instanceof OID4VPAuthenticationToken){
            principal = validateAuthenticationManagerToken(principal, scopes, authorizeRequest);
        }
        else if(principal instanceof UsernamePasswordAuthenticationTokenExtended){
            principal = validateUsernamePasswordAuthenticationTokenExtended(principal, scopes, authorizeRequest);
        }

        logger.info("Principal present: {}", principal);

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationToken =
              new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getRequestURL().toString(),
                    authorizeRequest.getClient_id(), principal, authorizeRequest.getRedirect_uri(),
                    authorizeRequest.getState(), scopes, additionalParameters);

        logger.info("OAuth2AuthorizationCodeRequestAuthenticationToken is generated.");
        return authorizationCodeRequestAuthenticationToken;
    }

    private boolean isSupportedAuthentication(Object principal) {
        return principal.getClass().equals(OID4VPAuthenticationToken.class) ||
              principal.getClass().equals(UsernamePasswordAuthenticationTokenExtended.class);
    }

    private Authentication validateAuthenticationManagerToken(Authentication principal, Set<String> scopes, OAuth2AuthorizeRequest authorizeRequest){
        logger.info("Authentication Principal is a AuthenticationManagerToken.");
        OID4VPAuthenticationToken token = (OID4VPAuthenticationToken) principal;

        boolean isInvalidBasic =
              !Objects.equals(authorizeRequest.getClient_id(), token.getClient_id()) ||
                    !Objects.equals(authorizeRequest.getRedirect_uri(), token.getRedirect_uri());

        boolean isInvalidCredential =
              !Objects.equals(authorizeRequest.getAuthorization_details(), token.getAuthorization_details()) ||
                    !Objects.equals(authorizeRequest.getHashes(), token.getHashDocument()) ||
                    !Objects.equals(authorizeRequest.getCredentialID(), token.getCredentialID()) ||
                    !Objects.equals(authorizeRequest.getHashAlgorithmOID(), token.getHashAlgorithmOID()) ||
                    !Objects.equals(authorizeRequest.getNumSignatures(), token.getNumSignatures());

        // if the request is of the scope "service" and the session does not contain the scope "service", the authentication is invalid...
        if(scopes.contains("service") && !Objects.equals(token.getScope(), "service")){
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
            logger.warn("AuthenticationManagerToken: Request Scope = 'service' && Token Request Scope != 'service'");
        }
        // if the clientId in the request doesn't match the clientId in the authentication, it is invalid...
        else if(isInvalidBasic){
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
            logger.warn("AuthenticationManagerToken: Basic Validation Failed.");
        }
        // if the request is of the scope "credential" and the session does not contain the scope "credential", the authentication is invalid...
        else if(scopes.contains("credential") && !Objects.equals(token.getScope(), "credential")) {
            logger.warn("AuthenticationManagerToken: Request Scope = 'credential' && Token Request Scope != 'credential'");
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }
        // if the request is of the scope "credential", but the requested information doesn't match the "authorized information", the authentication is invalid...
        else if(scopes.contains("credential") && isInvalidCredential){
            logger.warn("AuthenticationManagerToken: Credential Validation Failed.");
			logger.warn("Authorization Details? {}", Objects.equals(authorizeRequest.getAuthorization_details(), token.getAuthorization_details()));
            logger.warn("Hashes? {}", Objects.equals(authorizeRequest.getHashes(), token.getHashDocument()));
            logger.warn("CredentialID? {}", Objects.equals(authorizeRequest.getCredentialID(), token.getCredentialID()) );
            logger.warn("HashAlgorithmOID? {}", Objects.equals(authorizeRequest.getHashAlgorithmOID(), token.getHashAlgorithmOID()));
            logger.warn("NumSignatures? {}", Objects.equals(authorizeRequest.getNumSignatures(), token.getNumSignatures()));

            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }
        return principal;
    }

    private Authentication validateUsernamePasswordAuthenticationTokenExtended(Authentication principal, Set<String> scopes, OAuth2AuthorizeRequest authorizeRequest){
        logger.info("Authentication Principal is a UsernamePasswordAuthenticationTokenExtended.");
        UsernamePasswordAuthenticationTokenExtended token = (UsernamePasswordAuthenticationTokenExtended) principal;

        boolean isInvalidBasic =
              !Objects.equals(authorizeRequest.getClient_id(), token.getClient_id()) ||
                    !Objects.equals(authorizeRequest.getRedirect_uri(), token.getRedirect_uri());

        boolean isInvalidCredential =
              !Objects.equals(authorizeRequest.getAuthorization_details(), token.getAuthorization_details()) ||
                    !Objects.equals(authorizeRequest.getHashes(), token.getHashDocument()) ||
                    !Objects.equals(authorizeRequest.getCredentialID(), token.getCredentialID()) ||
                    !Objects.equals(authorizeRequest.getHashAlgorithmOID(), token.getHashAlgorithmOID()) ||
                    !Objects.equals(authorizeRequest.getNumSignatures(), token.getNumSignatures());

        // if the request is of the scope "service" and the session does not contain the scope "service", the authentication is invalid...
        if(scopes.contains("service") && !Objects.equals(token.getScope(), "service")){
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
            logger.warn("UsernamePasswordAuthenticationTokenExtended: Request Scope = 'service' && Token Request Scope != 'service'");
        }
        // if the clientId in the request doesn't match the clientId in the authentication, it is invalid...
        else if(isInvalidBasic){
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
            logger.warn("UsernamePasswordAuthenticationTokenExtended: Basic Validation Failed.");
        }
        // if the request is of the scope "credential" and the session does not contain the scope "credential", the authentication is invalid...
        else if(scopes.contains("credential") && !Objects.equals(token.getScope(), "credential")) {
            logger.warn("UsernamePasswordAuthenticationTokenExtended: Request Scope = 'credential' && Token Request Scope != 'credential'");
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }
        // if the request is of the scope "credential", but the requested information doesn't match the "authorized information", the authentication is invalid...
        else if(scopes.contains("credential") && isInvalidCredential){
            logger.warn("UsernamePasswordAuthenticationTokenExtended: Credential Validation Failed.");
            logger.warn("Authorization Details? {}", Objects.equals(authorizeRequest.getAuthorization_details(), token.getAuthorization_details()));
            logger.warn("Hashes? {}", Objects.equals(authorizeRequest.getHashes(), token.getHashDocument()));
            logger.warn("CredentialID? {}", Objects.equals(authorizeRequest.getCredentialID(), token.getCredentialID()) );
            logger.warn("HashAlgorithmOID? {}", Objects.equals(authorizeRequest.getHashAlgorithmOID(), token.getHashAlgorithmOID()));
            logger.warn("NumSignatures? {}", Objects.equals(authorizeRequest.getNumSignatures(), token.getNumSignatures()));
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }

        return principal;
    }

    private static Map<String, Object> getAdditionalParameters(OAuth2AuthorizeRequest authorizeRequest) {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("authorization_details", authorizeRequest.getAuthorization_details());
        additionalParameters.put("code_challenge", authorizeRequest.getCode_challenge());
        additionalParameters.put("code_challenge_method", authorizeRequest.getCode_challenge_method());
        additionalParameters.put("lang", authorizeRequest.getLang());
        additionalParameters.put("credentialID", authorizeRequest.getCredentialID());
        additionalParameters.put("signatureQualifier", authorizeRequest.getSignatureQualifier());
        additionalParameters.put("numSignatures", authorizeRequest.getNumSignatures());
        additionalParameters.put("hashes", authorizeRequest.getHashes());
        additionalParameters.put("hashAlgorithmOID", authorizeRequest.getHashAlgorithmOID());
        additionalParameters.put("description", authorizeRequest.getDescription());
        additionalParameters.put("account_token", authorizeRequest.getAccount_token());
        additionalParameters.put("clientData", authorizeRequest.getClientData());
        return additionalParameters;
    }
}
