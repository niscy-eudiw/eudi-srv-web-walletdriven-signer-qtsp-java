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

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.credentials.CredentialsService;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.util.OAuth2ValidationUtils;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2ScopesNames;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;

public class TokenRequestProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final CredentialsService credentialsService;
    private final Logger logger = LoggerFactory.getLogger(TokenRequestProvider.class);

    public TokenRequestProvider(OAuth2AuthorizationService authorizationService,
                                OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                CredentialsService credentialsService) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.credentialsService = credentialsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeAuthenticationToken oauth2TokenRequest = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

        // --- Retrieved necessary tokens (from oauth2/authorize request) from db ---

        OAuth2ClientAuthenticationToken clientAuthentication = getAuthenticatedClientToken(oauth2TokenRequest);
        RegisteredClient tokenRequestAuthenticatedClient = clientAuthentication.getRegisteredClient();

        OAuth2Authorization authorization = this.authorizationService.findByToken(oauth2TokenRequest.getCode(), new OAuth2TokenType(OAuth2ParameterNames.CODE));
        if (authorization == null)
            throw new OAuth2AuthenticationException(
                  OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "Invalid parameter code."));
        logger.info("Retrieved representation of an OAuth2.0 Authorization with authorization code: {}", oauth2TokenRequest.getCode());

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        if(authorizationCode == null)
            throw new OAuth2AuthenticationException(
                  OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT, "Authorization code is invalid or expired."));
        logger.debug("Retrieved OAuth2AuthorizationCode Token.");

        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        if(authorizationRequest == null)
            throw new OAuth2AuthenticationException(OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "No authorization request found."));
        logger.debug("Retrieved representation of an OAuth2.0 Authorization Request.");

        // --- Validate Token Request ---

        // checks if oauth2/token client (currently authenticated) is the same of oauth2/authorize client
        tokenClientMatchesAuthorizeClient(tokenRequestAuthenticatedClient, authorizationRequest.getClientId(), authorization, authorizationCode);

        // checks the redirect_uri in the token request is equal to the one in the authorization request
        String authorizeRedirectUri = authorizationRequest.getRedirectUri();
        String tokenRedirectUri = oauth2TokenRequest.getRedirectUri();
        OAuth2ValidationUtils.validateRedirectUri(logger, authorizeRedirectUri, tokenRedirectUri);

        // checks if authorization code is still active
        validateActiveCode(authorizationCode, authorization);

        // checks PKCE: if code_verifier from oauth2/token can be used to validate code_challenge from oauth2/authorize
        OAuth2ValidationUtils.validatePKCE(logger, authorizationRequest.getAdditionalParameters(), oauth2TokenRequest.getAdditionalParameters());

        // is Authorization Details valid: if the authorization details are set in oauth2/authorize, in oauth2/token authorization_details should be also present and equal
        Map<String, Object> additionalParameters = authorizationRequest.getAdditionalParameters();
        Object authorizeRequestAuthorizationDetails = additionalParameters.get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS);
        if(authorization.getAuthorizedScopes().contains(OAuth2ScopesNames.CREDENTIAL) && authorizeRequestAuthorizationDetails != null) {
            Object tokenRequestAuthorizationDetails = oauth2TokenRequest.getAdditionalParameters().get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS);
            OAuth2ValidationUtils.validateAuthorizationDetails(logger, authorizeRequestAuthorizationDetails, tokenRequestAuthorizationDetails);
        }

        logger.info("OAuth2 Token Request is valid.");

        // Get Resource Owner Authentication
        Authentication principal = authorization.getAttribute(Principal.class.getName());
        logger.info("Resource Owner: {}", principal);

        // Update additional parameters with credential id if signature qualifier is used
        if (authorizeRequestAuthorizationDetails != null) {
            Map<String, Object> additionalParametersChangeable = new HashMap<>(additionalParameters);
            OAuth2ValidationUtils.addCredentialIdFromSignatureQualifierToAuthorizationDetails(logger, credentialsService, principal, additionalParametersChangeable, authorizeRequestAuthorizationDetails.toString());
            authorizationRequest = OAuth2AuthorizationRequest.from(authorizationRequest).additionalParameters(additionalParametersChangeable).build();
            authorization =  OAuth2Authorization.from(authorization).attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest).build();
        }

        // ----- Issuing Access token -----
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
              .registeredClient(tokenRequestAuthenticatedClient)
              .principal(principal)
              .authorizationServerContext(AuthorizationServerContextHolder.getContext())
              .authorization(authorization)
              .authorizedScopes(authorization.getAuthorizedScopes())
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrant(oauth2TokenRequest);
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

        OAuth2AccessToken accessToken = generateAccessToken(authorizationBuilder, tokenContext, authorization.getAuthorizedScopes());

        // Invalidate the authorization code as it can only be used once
        authorizationBuilder.invalidate(authorizationCode.getToken());
        authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);

        return getAccessTokenAuthenticationToken(accessToken, tokenRequestAuthenticatedClient, clientAuthentication, authorizationRequest);
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientToken(Authentication authentication) throws OAuth2AuthenticationException{
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass()))
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        if (clientPrincipal != null && clientPrincipal.isAuthenticated())
            return clientPrincipal;
        throw new OAuth2AuthenticationException(OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_CLIENT,
              "The client was not authenticated."));
    }

    // verifies that oauth2/token client is the same of oauth2/authorize client
    private void tokenClientMatchesAuthorizeClient(RegisteredClient tokenRequestClient, String authorizeRequestClientId,
                                                   OAuth2Authorization authorization, OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode){

        if (!tokenRequestClient.getClientId().equals(authorizeRequestClientId)) {
            if (!authorizationCode.isInvalidated()) {
                authorization =  OAuth2Authorization.from(authorization)
                      .invalidate(authorizationCode.getToken())
                      .build();
                this.authorizationService.save(authorization);
                logger.error("Invalidated authorization code used by registered client {}", tokenRequestClient.getId());
            }
            throw new OAuth2AuthenticationException(
                  OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "The client that requested the code is not the same as the one requesting the access token"));
        }
        logger.info("Validated that the client that requested the code is the same as the one requesting the access token.");
    }

    // verifies if the current authorization code saved is still active
    private void validateActiveCode(OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode, OAuth2Authorization authorization){
        if (!authorizationCode.isActive()) {
            if (authorizationCode.isInvalidated()) {
                OAuth2Authorization.Token<? extends OAuth2Token> token = (authorization.getRefreshToken() != null) ? authorization.getRefreshToken() : authorization.getAccessToken();
                if(token != null) {
                    authorization = OAuth2Authorization.from(authorization).invalidate(token.getToken()).build();
                    this.authorizationService.save(authorization);
                    logger.warn("Invalidated authorization token(s) previously issued");
                }
            }
            throw new OAuth2AuthenticationException(
                  OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT, "Authorization code is invalid or expired."));
        }
    }

    private OAuth2AccessToken generateAccessToken(OAuth2Authorization.Builder authorizationBuilder, OAuth2TokenContext tokenContext, Set<String> scopes){

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                  OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token."));
        }

        OAuth2AccessToken accessToken;
        if(scopes.contains(OAuth2ScopesNames.SERVICE)){
            Instant expiresAt = generatedAccessToken.getIssuedAt().plus(1L, ChronoUnit.HOURS);
            accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generatedAccessToken.getTokenValue(),
                  generatedAccessToken.getIssuedAt(), expiresAt, tokenContext.getAuthorizedScopes());
        }
        else{
            accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generatedAccessToken.getTokenValue(),
                  generatedAccessToken.getIssuedAt(), generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        }

        OAuth2TokenFormat accessTokenFormat = tokenContext.getRegisteredClient().getTokenSettings().getAccessTokenFormat();
        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) -> {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
                metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
                metadata.put(OAuth2TokenFormat.class.getName(), accessTokenFormat.getValue());
            });
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        return  accessToken;
    }

    private OAuth2AccessTokenAuthenticationToken getAccessTokenAuthenticationToken(OAuth2AccessToken accessToken,
                                                                                   RegisteredClient registeredClient,
                                                                                   OAuth2ClientAuthenticationToken clientPrincipal,
                                                                                   OAuth2AuthorizationRequest authorizationRequest){
        OAuth2AccessTokenAuthenticationToken accessTokenAuthenticationToken;
        if(authorizationRequest.getAdditionalParameters().get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS) != null) {
            String authDetailsToken = authorizationRequest.getAdditionalParameters().get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS).toString();
            Map<String, Object> additionalParameters = new HashMap<>();
            JSONArray authDetailsTokenArray = new JSONArray(authDetailsToken);
            List<Object> authDetailsList = authDetailsTokenArray.toList();
            additionalParameters.put(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, authDetailsList);
            accessTokenAuthenticationToken = new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null, additionalParameters);
        }
        else if(authorizationRequest.getAdditionalParameters().get(OAuth2CustomParameterNames.SIGNATURE_QUALIFIER) != null){
            Map<String, Object> additionalParameters = new HashMap<>();
            String credentialID = authorizationRequest.getAdditionalParameters().get(OAuth2CustomParameterNames.CREDENTIAL_ID).toString();
            additionalParameters.put(OAuth2CustomParameterNames.CREDENTIAL_ID, credentialID);
            accessTokenAuthenticationToken = new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null, additionalParameters);
        }
        else accessTokenAuthenticationToken = new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null, Collections.emptyMap());
        logger.info("Authenticate TokenRequest and generated an OAuth2AccessTokenAuthenticationToken.");
        return accessTokenAuthenticationToken;
    }

}
