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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.provider;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.credentials.CredentialsService;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.ManageOAuth2Authorization;

import java.security.Principal;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.util.OAuth2ValidationUtils;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2ScopesNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;

public class AuthorizationRequestProvider implements AuthenticationProvider {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
    private final OAuth2AuthorizationService authorizationService;
    private final ManageOAuth2Authorization manageOAuth2Authorization;
    private final CredentialsService credentialsService;
    private final Logger logger = LoggerFactory.getLogger(AuthorizationRequestProvider.class);

    private static class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {

        private final StringKeyGenerator authorizationCodeGenerator = new Base64StringKeyGenerator(
                Base64.getUrlEncoder().withoutPadding(), 96);

        @Nullable
        @Override
        public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
            if (context.getTokenType() == null
                    || !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt
                    .plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
            return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
        }
    }

    public AuthorizationRequestProvider(RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            ManageOAuth2Authorization manageOAuth2Authorization,
            CredentialsService credentialsService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.manageOAuth2Authorization = manageOAuth2Authorization;
        this.credentialsService = credentialsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken oAuth2AuthorizeRequestToken = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        logger.info("Authenticating an Authorization Code Request for the clientID: {}.",
                oAuth2AuthorizeRequestToken.getClientId());

        // Found registered client with client_id from oauth2/authorize
        RegisteredClient registeredClient = this.registeredClientRepository
                .findByClientId(oAuth2AuthorizeRequestToken.getClientId());
        if (registeredClient == null) {
            OAuth2Error error = OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                    "ClientId " + oAuth2AuthorizeRequestToken.getClientId() + " from the request not found.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, oAuth2AuthorizeRequestToken);
        }

        // Check if 'authorization_code' is supported and retrieve GrantType
        isAuthorizationCodeSupported(registeredClient, oAuth2AuthorizeRequestToken);

        // Get redirect_uri from oauth2/authorize or from pre-registered client
        String requestedRedirectUri = oAuth2AuthorizeRequestToken.getRedirectUri();
        String redirectUri = OAuth2ValidationUtils.resolveRedirectUri(logger, registeredClient, requestedRedirectUri,
                oAuth2AuthorizeRequestToken);

        // Get requested scopes in oauth2/authorize
        Set<String> requestedScopes = resolveAndValidateScopes(registeredClient, oAuth2AuthorizeRequestToken);

        // Validates if PKCE parameters are present and supported
        OAuth2ValidationUtils.validatePKCE(logger, oAuth2AuthorizeRequestToken);

        // Verifies if the Authorization Details in the oauth2/authorize request is
        // valid
        String authorizationDetails = (String) oAuth2AuthorizeRequestToken.getAdditionalParameters()
                .get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS);
        if (authorizationDetails != null)
            OAuth2ValidationUtils.isAuthorizationDetailsValid(logger, authorizationDetails,
                    oAuth2AuthorizeRequestToken);

        // After verifying the request is valid, ensures the resource owner is
        // authenticated
        Authentication principal = (Authentication) oAuth2AuthorizeRequestToken.getPrincipal();
        if (!isPrincipalAuthenticated(principal)) {
            logger.warn("Did not authenticate authorizationCode request since principal not authenticated");
            return oAuth2AuthorizeRequestToken;
        }

        // Update additional parameters with credential id if signature qualifier is
        // used
        Map<String, Object> additionalParameters = oAuth2AuthorizeRequestToken.getAdditionalParameters();
        if (oAuth2AuthorizeRequestToken.getScopes().contains(OAuth2ScopesNames.CREDENTIAL))
            OAuth2ValidationUtils.addCredentialIdFromSignatureQualifier(logger, credentialsService, principal,
                    additionalParameters);

        // For credential_creation and credential_delete, no credential-id resolution
        // needed —
        // those flows create or remove the credential rather than signing with an
        // existing one.
        if (oAuth2AuthorizeRequestToken.getScopes().contains(OAuth2ScopesNames.CREDENTIAL_CREATION)) {
            logger.info("Processing credential_creation authorization request.");
        }
        if (oAuth2AuthorizeRequestToken.getScopes().contains(OAuth2ScopesNames.CREDENTIAL_DELETION)) {
            logger.info("Processing credential_delete authorization request.");
        }

        // Remove previous oauth2/authorize request to keep the database clean
        this.manageOAuth2Authorization.removePreviousOAuth2AuthorizationOfUser(principal.getName(), requestedScopes);

        // Generates all objects with authorization and that will be required for
        // oauth2/token
        OAuth2AuthorizationRequest oAuth2AuthorizeRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(oAuth2AuthorizeRequestToken.getAuthorizationUri())
                .clientId(registeredClient.getClientId())
                .redirectUri(redirectUri)
                .scopes(requestedScopes)
                .state(oAuth2AuthorizeRequestToken.getState())
                .additionalParameters(additionalParameters)
                .build();
        logger.info("Generated a representation of an OAuth2.0 Authorization Request.");

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
                .authorizedScopes(requestedScopes)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(oAuth2AuthorizeRequestToken);
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null)
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.SERVER_ERROR,
                            "The token generator failed to generate the authorization code."),
                    null);
        logger.info("Generated OAuth2AuthorizationCode.");

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(principal.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), principal)
                .attribute(OAuth2AuthorizationRequest.class.getName(), oAuth2AuthorizeRequest)
                .authorizedScopes(requestedScopes)
                .token(authorizationCode)
                .build();
        logger.info("Generated representation of an OAuth2.0 Authorization.");
        this.authorizationService.save(authorization);

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                oAuth2AuthorizeRequest.getAuthorizationUri(),
                registeredClient.getClientId(),
                principal,
                authorizationCode,
                redirectUri,
                oAuth2AuthorizeRequest.getState(),
                requestedScopes);
    }

    // This functions checks if the grant_type 'authorization_code' is supported by
    // pre-registered client
    private void isAuthorizationCodeSupported(RegisteredClient registeredClient,
            OAuth2AuthorizationCodeRequestAuthenticationToken token) {
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            OAuth2Error error = OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                    "Request grant_type 'authorization_code' is not allowed for the registered client.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, token);
        }
    }

    // Checks if scopes are defined in oauth2/authorize and if they are supported
    private Set<String> resolveAndValidateScopes(RegisteredClient registeredClient,
            OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken) {
        Set<String> requestedScopes = authenticationToken.getScopes();
        if (CollectionUtils.isEmpty(requestedScopes))
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                            "The 'scope' parameter is missing."),
                    authenticationToken);

        if (!registeredClient.getScopes().containsAll(requestedScopes)) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_SCOPE,
                            "The scope requested is not supported."),
                    authenticationToken);
        }
        return requestedScopes;
    }

    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
                && principal.isAuthenticated();
    }
}
