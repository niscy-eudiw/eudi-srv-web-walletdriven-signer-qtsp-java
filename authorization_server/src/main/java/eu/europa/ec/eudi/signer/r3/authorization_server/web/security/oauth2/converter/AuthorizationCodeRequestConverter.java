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
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2ScopesNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.OID4VPAuthenticationToken;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token.ICommonTokenStructure;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Attempts to extract an Authorization Request from HttpServletRequest for the
 * OAuth 2.0 Authorization Code Grant and then converts it to an
 * OAuth2AuthorizationCodeRequestAuthenticationToken used for authenticating
 * the request.
 */
public class AuthorizationCodeRequestConverter implements AuthenticationConverter {
    private final RequestMatcher authenticationServiceRequestMatcher;
    private final RequestMatcher authorizationCredentialRequestMatcher;
    private final RequestMatcher authorizationCredentialCreationRequestMatcher;
    private final RequestMatcher authorizationCredentialDeleteRequestMatcher;
    private final RequestMatcher withoutScopeOrAuthorizationDetailsRequestMatcher;
    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
            "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final Logger logger = LoggerFactory.getLogger(AuthorizationCodeRequestConverter.class);

    public AuthorizationCodeRequestConverter() {
        RequestMatcher serviceRequestMatcher = OAuth2AuthorizeRequest.requestMatcherForService();
        this.authenticationServiceRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(
                        "/oauth2/authorize", HttpMethod.GET.name()),
                serviceRequestMatcher);

        RequestMatcher credentialsRequestMatcher = OAuth2AuthorizeRequest.requestMatcherForCredential();
        this.authorizationCredentialRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(
                        "/oauth2/authorize", HttpMethod.GET.name()),
                credentialsRequestMatcher);

        // New: credential-creation scope matcher (1.1.2)
        RequestMatcher credentialCreationRequestMatcher = OAuth2AuthorizeRequest.requestMatcherForCredentialCreation();
        this.authorizationCredentialCreationRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(
                        "/oauth2/authorize", HttpMethod.GET.name()),
                credentialCreationRequestMatcher);

        // New: credential-delete scope matcher (1.1.3)
        RequestMatcher credentialDeleteRequestMatcher = OAuth2AuthorizeRequest.requestMatcherForCredentialDelete();
        this.authorizationCredentialDeleteRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(
                        "/oauth2/authorize", HttpMethod.GET.name()),
                credentialDeleteRequestMatcher);

        // neither the scope nor the authorization_details are required, if neither is
        // present the scope defaults to "service"
        RequestMatcher withoutScopeOrAuthorizationDetails = OAuth2AuthorizeRequest
                .requestMatcherWithoutScopeOrAuthorizationDetails();
        this.withoutScopeOrAuthorizationDetailsRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(
                        "/oauth2/authorize", HttpMethod.GET.name()),
                withoutScopeOrAuthorizationDetails);
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        logger.info("Request received at {}", request.getRequestURL().toString());
        logger.info(request.getQueryString());
        if (!this.authenticationServiceRequestMatcher.matches(request) &&
                !this.authorizationCredentialRequestMatcher.matches(request) &&
                !this.authorizationCredentialCreationRequestMatcher.matches(request) &&
                !this.authorizationCredentialDeleteRequestMatcher.matches(request) &&
                !this.withoutScopeOrAuthorizationDetailsRequestMatcher.matches(request)) {
            if (!request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)
                    .equals(OAuth2AuthorizationResponseType.CODE.getValue())) {
                String error_description = "The response type in the request is not supported.";
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, error_description,
                        null);
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

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            logger.warn("Authentication is not present. The user is not authenticated.");
            principal = ANONYMOUS_AUTHENTICATION;
        } else if (!isSupportedAuthentication(principal)) {
            logger.warn("Authentication present is not valid. The authentication mechanism is not the supported.");
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        } else if (principal instanceof OID4VPAuthenticationToken) {
            logger.info("Authentication Principal is a AuthenticationManagerToken.");
            principal = validateSupportedAuthentication("AuthenticationManagerToken", principal,
                    Collections.singleton(authorizeRequest.getScope()), authorizeRequest);
        } else if (principal instanceof UsernamePasswordAuthenticationTokenExtended) {
            logger.info("Authentication Principal is a UsernamePasswordAuthenticationTokenExtended.");
            principal = validateSupportedAuthentication("UsernamePasswordAuthenticationTokenExtended", principal,
                    Collections.singleton(authorizeRequest.getScope()), authorizeRequest);
        }
        logger.info("Resource Owner Authentication: {}", principal);

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationToken = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                request.getRequestURL().toString(),
                authorizeRequest.getClient_id(),
                principal,
                authorizeRequest.getRedirect_uri(),
                authorizeRequest.getState(),
                Collections.singleton(authorizeRequest.getScope()),
                additionalParameters);
        logger.info("OAuth2AuthorizationCodeRequestAuthenticationToken is generated.");
        return authorizationCodeRequestAuthenticationToken;
    }

    private boolean isSupportedAuthentication(Object principal) {
        return principal.getClass().equals(OID4VPAuthenticationToken.class) ||
                principal.getClass().equals(UsernamePasswordAuthenticationTokenExtended.class);
    }

    private Authentication validateSupportedAuthentication(String type, Authentication principal, Set<String> scopes,
            OAuth2AuthorizeRequest authorizeRequest) {
        ICommonTokenStructure token = (ICommonTokenStructure) principal;

        boolean isInvalidBasic = !Objects.equals(authorizeRequest.getClient_id(), token.getClient_id()) ||
                !Objects.equals(authorizeRequest.getRedirect_uri(), token.getRedirect_uri());

        boolean isInvalidCredential = !Objects.equals(authorizeRequest.getAuthorization_details(),
                token.getAuthorization_details()) ||
                !Objects.equals(authorizeRequest.getHashes(), token.getHashDocument()) ||
                !Objects.equals(authorizeRequest.getCredentialID(), token.getCredentialID()) ||
                !Objects.equals(authorizeRequest.getHashAlgorithmOID(), token.getHashAlgorithmOID()) ||
                !Objects.equals(authorizeRequest.getNumSignatures(), token.getNumSignatures());

        // if the request is of the scope "service" and the session does not contain the
        // scope "service", the authentication is invalid...
        if (scopes.contains(OAuth2ScopesNames.SERVICE) && !Objects.equals(token.getScope(), OAuth2ScopesNames.SERVICE)) {
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
            logger.warn("{}: Request Scope = 'service' && Token Request Scope != 'service'", type);
        }
        // if the clientId in the request doesn't match the clientId in the
        // authentication, it is invalid...
        else if (isInvalidBasic) {
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
            logger.warn("{}: Basic Validation Failed.", type);
        }
        // if the request is of the scope "credential" and the session does not contain
        // the scope "credential", the authentication is invalid...
        else if (scopes.contains(OAuth2ScopesNames.CREDENTIAL) && !Objects.equals(token.getScope(), OAuth2ScopesNames.CREDENTIAL)) {
            logger.warn("{}: Request Scope = 'credential' && Token Request Scope != 'credential'", type);
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }
        // if the request is of the scope "credential", but the requested information
        // doesn't match the "authorized information", the authentication is invalid...
        else if (scopes.contains(OAuth2ScopesNames.CREDENTIAL) && isInvalidCredential) {
            logger.warn("{}: Credential Validation Failed.", type);
            logger.warn("Authorization Details? {}", Objects.equals(authorizeRequest.getAuthorization_details(), token.getAuthorization_details()));
            logger.warn("Hashes? {}", Objects.equals(authorizeRequest.getHashes(), token.getHashDocument()));
            logger.warn("CredentialID? {}", Objects.equals(authorizeRequest.getCredentialID(), token.getCredentialID()));
            logger.warn("HashAlgorithmOID? {}", Objects.equals(authorizeRequest.getHashAlgorithmOID(), token.getHashAlgorithmOID()));
            logger.warn("NumSignatures? {}", Objects.equals(authorizeRequest.getNumSignatures(), token.getNumSignatures()));
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }
        // if the request is of the scope "credential_creation" and the session does not
        // contain that scope, the authentication is invalid...
        else if (scopes.contains(OAuth2ScopesNames.CREDENTIAL_CREATION) && !Objects.equals(token.getScope(), OAuth2ScopesNames.CREDENTIAL_CREATION)) {
            logger.warn("{}: Request Scope = 'credential_creation' && Token Request Scope != 'credential_creation'", type);
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }
        // if the request is of the scope "credential_delete" and the session does not
        // contain that scope, the authentication is invalid...
        else if (scopes.contains(OAuth2ScopesNames.CREDENTIAL_DELETION) && !Objects.equals(token.getScope(), OAuth2ScopesNames.CREDENTIAL_DELETION)) {
            logger.warn("{}: Request Scope = 'credential_delete' && Token Request Scope != 'credential_delete'", type);
            principal = ANONYMOUS_AUTHENTICATION;
            SecurityContextHolder.clearContext();
        }
        return principal;
    }

    private static Map<String, Object> getAdditionalParameters(OAuth2AuthorizeRequest authorizeRequest) {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS,
                authorizeRequest.getAuthorization_details());
        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, authorizeRequest.getCode_challenge());
        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, authorizeRequest.getCode_challenge_method());
        additionalParameters.put(OAuth2CustomParameterNames.LANG, authorizeRequest.getLang());
        additionalParameters.put(OAuth2CustomParameterNames.CREDENTIAL_ID, authorizeRequest.getCredentialID());
        additionalParameters.put(OAuth2CustomParameterNames.SIGNATURE_QUALIFIER,
                authorizeRequest.getSignatureQualifier());
        additionalParameters.put(OAuth2CustomParameterNames.NUM_SIGNATURES, authorizeRequest.getNumSignatures());
        additionalParameters.put(OAuth2CustomParameterNames.HASHES, authorizeRequest.getHashes());
        additionalParameters.put(OAuth2CustomParameterNames.HASH_ALGORITHM_OID, authorizeRequest.getHashAlgorithmOID());
        additionalParameters.put(OAuth2CustomParameterNames.DESCRIPTION, authorizeRequest.getDescription());
        additionalParameters.put(OAuth2CustomParameterNames.ACCOUNT_TOKEN, authorizeRequest.getAccount_token());
        additionalParameters.put(OAuth2CustomParameterNames.CLIENT_DATA, authorizeRequest.getClientData());
        return additionalParameters;
    }
}
