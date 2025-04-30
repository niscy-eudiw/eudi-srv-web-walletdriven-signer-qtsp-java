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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
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
import org.springframework.util.StringUtils;

public class TokenRequestProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final Logger logger = LogManager.getLogger(TokenRequestProvider.class);

    private OAuth2Error getOAuth2Error(String errorCode, String errorDescription){
        logger.error(errorDescription);
        return new OAuth2Error(errorCode, errorDescription, null);
    }

    public TokenRequestProvider(OAuth2AuthorizationService authorizationService,
                                OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(authorizationCodeAuthentication);

        // get the registered client that made the token request
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        logger.info("Authenticating OAuth2AuthorizationCodeAuthenticationToken from clientID: {}", registeredClient.getClientId());

        // load the authorization request with the code received
        OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCodeAuthentication.getCode(), new OAuth2TokenType(OAuth2ParameterNames.CODE));
        if (authorization == null){
            throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid parameter code."));
        }
        logger.info("Retrieved authorization with authorization code: {}", authorization.getToken(OAuth2AuthorizationCode.class));

        // get the authorization request itself
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        if(authorizationCode == null){
            throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Authorization code is invalid or expired."));
        }

        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        if(authorizationRequest == null){
            throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "No authorization request found."));
        }

        // verifies that the client that requested the code is the same to the one requesting the access token
        if (!registeredClient.getClientId().equals(authorizationRequest.getClientId())) {
            if (!authorizationCode.isInvalidated()) {
                authorization = invalidate(authorization, authorizationCode.getToken());
                this.authorizationService.save(authorization);
                logger.error("Invalidated authorization code used by registered client {}", registeredClient.getId());
            }
            throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "The client that requested the code is not the same as the one requesting the access token"));
        }
        logger.info("Validated that the client that requested the code is the same as the one requesting the access token.");

        // Validates that the redirect uri in the token request is equal to the one in the authorization request
        if (StringUtils.hasText(authorizationRequest.getRedirectUri()) && !authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
            throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "redirect_uri does not match the redirect_uri parameter of authorization request."));
        }
        logger.info("Validated that the redirect_uri matches the registered client redirect_uri.");

        // verifies if the current authorization code saved is still active
        if (!authorizationCode.isActive()) {
            if (authorizationCode.isInvalidated()) {
                OAuth2Authorization.Token<? extends OAuth2Token> token = (authorization.getRefreshToken() != null) ? authorization.getRefreshToken() : authorization.getAccessToken();
                if(token != null) {
                    authorization = invalidate(authorization, token.getToken());
                    this.authorizationService.save(authorization);
                    logger.warn("Invalidated authorization token(s) previously issued to registered client {}", registeredClient.getId());
                }
            }
            throw new OAuth2AuthenticationException(
                  getOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Authorization code is invalid or expired."));
        }

        // verify the code_challenge
        String code_challenge = authorizationRequest.getAdditionalParameters().get("code_challenge").toString();
        String code_challenge_method = authorizationRequest.getAdditionalParameters().get("code_challenge_method").toString();
        String code_verifier = authorizationCodeAuthentication.getAdditionalParameters().get("code_verifier").toString();
        if (code_challenge == null || code_challenge_method == null || code_verifier == null)
            throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Code_challenge or Code_verifier missing."));
        logger.info("Code_Challenge: {}; Code_Challenge_Method: {}; Code_Verifier: {}", code_challenge, code_challenge_method, code_verifier);

        // Validate PKCE
        if (code_challenge_method.equals("S256")) {
            String code_challenge_calculated;
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] result = sha.digest(code_verifier.getBytes());
                code_challenge_calculated = Base64.getUrlEncoder().withoutPadding().encodeToString(result);
                logger.info("Code_Challenge_Calculated: {}", code_challenge_calculated);
            } catch (Exception e) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            if (!Objects.equals(code_challenge_calculated, code_challenge)) {
                throw new OAuth2AuthenticationException(
                      getOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "The code verifier doesn't validate the previous code challenge."));
            }
        } else if (code_challenge_method.equals("plain")) {
            if (!Objects.equals(code_verifier, code_challenge)) {
                throw new OAuth2AuthenticationException(
                      getOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "The code verifier doesn't validate the previous code challenge."));
            }
        }
        logger.info("Validated the code verifier.");

        // Validate Authorization Details: if the authorization details are set in the previous request, that should know be also present and be equal
        if(authorization.getAuthorizedScopes().contains("credential") && authorizationRequest.getAdditionalParameters().get("authorization_details") != null) {
            if (authorizationRequest.getAdditionalParameters().get("authorization_details") != null && authorizationCodeAuthentication.getAdditionalParameters().get("authorization_details") == null) {
                throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "The Authorization Details from the tokenRequest doesn't match the Authorization Details from the authorizationRequest."));
            } else {
                String authDetailsAuthorization = URLDecoder.decode(authorizationRequest.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);
                String authDetailsToken = URLDecoder.decode(authorizationCodeAuthentication.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);

                JSONArray authDetailsAuthorizationArray = new JSONArray(authDetailsAuthorization);
                JSONObject authDetailsAuthorizationJSON = authDetailsAuthorizationArray.getJSONObject(0);

                JSONArray authDetailsTokenArray = new JSONArray(authDetailsToken);
                JSONObject authDetailsTokenJSON = authDetailsTokenArray.getJSONObject(0);

                if (!authDetailsAuthorizationJSON.similar(authDetailsTokenJSON)) {
                    throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "The Authorization Details from the tokenRequest doesn't match the Authorization Details from the authorizationRequest."));
                }
            }
            logger.info("Validated Authorization_details");
        }
        logger.info("Token Request is valid.");

        // ----- Access token -----
        return accessTokenGeneration(authorization, registeredClient, authorizationCodeAuthentication, authorizationCode, clientPrincipal, authorizationRequest);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
              "The client was not authenticated."));
    }

    private static <T extends OAuth2Token> OAuth2Authorization invalidate(OAuth2Authorization authorization, T token) {
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
              .token(token,
                    (metadata) ->
                          metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

        if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
            authorizationBuilder.token(
                  authorization.getAccessToken().getToken(),
                  (metadata) ->
                        metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                  authorization.getToken(OAuth2AuthorizationCode.class);
            if (authorizationCode != null && !authorizationCode.isInvalidated()) {
                authorizationBuilder.token(
                      authorizationCode.getToken(),
                      (metadata) ->
                            metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
            }
        }
        return authorizationBuilder.build();
    }

    private OAuth2AccessTokenAuthenticationToken accessTokenGeneration(
          OAuth2Authorization authorization, RegisteredClient registeredClient,
          OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication,
          OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode,
          OAuth2ClientAuthenticationToken clientPrincipal, OAuth2AuthorizationRequest authorizationRequest){

        Authentication principal = authorization.getAttribute(Principal.class.getName());
		logger.info("Principal Info: {}", principal.toString());

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
              .registeredClient(registeredClient)
              .principal(principal)
              .authorizationServerContext(AuthorizationServerContextHolder.getContext())
              .authorization(authorization)
              .authorizedScopes(authorization.getAuthorizedScopes())
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrant(authorizationCodeAuthentication)
              .tokenType(OAuth2TokenType.ACCESS_TOKEN);

        DefaultOAuth2TokenContext tokenContext = tokenContextBuilder.build();
        logger.info("Generate TokenContext.");

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                  getOAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token."));
        }

        OAuth2AccessToken accessToken;
        if(authorization.getAuthorizedScopes().contains("service")){
            Instant expiresAt = generatedAccessToken.getIssuedAt().plus(1L, ChronoUnit.HOURS);
            accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generatedAccessToken.getTokenValue(),
                  generatedAccessToken.getIssuedAt(), expiresAt, tokenContext.getAuthorizedScopes());
        }
        else{
            accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generatedAccessToken.getTokenValue(),
                  generatedAccessToken.getIssuedAt(), generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        }

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) -> {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
                metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
                metadata.put(OAuth2TokenFormat.class.getName(), tokenContext.getRegisteredClient().getTokenSettings().getAccessTokenFormat().getValue());
            });
        } else {
            authorizationBuilder.accessToken(accessToken);
        }
        authorization = authorizationBuilder.build();

        // Invalidate the authorization code as it can only be used once
        authorization = invalidate(authorization, authorizationCode.getToken());
        this.authorizationService.save(authorization);
        logger.info("Saved Authorization");

        OAuth2AccessTokenAuthenticationToken accessTokenAuthenticationToken;

        System.out.println(authorizationCodeAuthentication.getAdditionalParameters().toString());
        System.out.println(authorizationRequest.getAdditionalParameters().get("signatureQualifier"));

        if(authorizationCodeAuthentication.getAdditionalParameters().get("authorization_details") != null) {
            String authDetailsToken = URLDecoder.decode(authorizationCodeAuthentication.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);
            Map<String, Object> additionalParameters = new HashMap<>();
            JSONArray authDetailsTokenArray = new JSONArray(authDetailsToken);
            List<Object> authDetailsList = authDetailsTokenArray.toList();
            additionalParameters.put("authorization_details", authDetailsList);
            accessTokenAuthenticationToken = new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null, additionalParameters);
        }
        else if(authorizationRequest.getAdditionalParameters().get("signatureQualifier") != null){
            Map<String, Object> additionalParameters = new HashMap<>();
            String credentialID = authorizationRequest.getAdditionalParameters().get("credentialID").toString();
            additionalParameters.put("credentialID", credentialID);
            accessTokenAuthenticationToken = new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null, additionalParameters);
        }
        else accessTokenAuthenticationToken = new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null);
        logger.info("Authenticate TokenRequest and generated an OAuth2AccessTokenAuthenticationToken.");
        return accessTokenAuthenticationToken;
    }
}
