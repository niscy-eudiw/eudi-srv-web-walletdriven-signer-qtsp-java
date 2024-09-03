package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.provider;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
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

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    private final OAuth2AuthorizationService authorizationService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final Logger logger = LogManager.getLogger(TokenRequestProvider.class);

    /**
     * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the
     * provided parameters.
     * @param authorizationService the authorization service
     * @since 0.2.3
     */
    public TokenRequestProvider(OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(authorizationCodeAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        logger.info("Retrieved registered client: " + registeredClient.getClientId());

        // Get the Authorization Request Information
        OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCodeAuthentication.getCode(), AUTHORIZATION_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        logger.info("Retrieved authorization with authorization code: " + authorization.getToken(OAuth2AuthorizationCode.class));
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

        // verifies that the client that requested the code is the same to the one requesting the access token
        if (!registeredClient.getClientId().equals(authorizationRequest.getClientId())) {
            if (!authorizationCode.isInvalidated()) {
                authorization = invalidate(authorization, authorizationCode.getToken());
                this.authorizationService.save(authorization);
                System.out.println(LogMessage.format("Invalidated authorization code used by registered client '%s'", registeredClient.getId()));
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // Validates that the redirect uri in the token request is equal to the one in the authorization request
        if (StringUtils.hasText(authorizationRequest.getRedirectUri()) && !authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
            System.out.println(LogMessage.format("Invalid request: redirect_uri does not match" + " for registered client '%s'", registeredClient.getClientId()));
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (!authorizationCode.isActive()) {
            if (authorizationCode.isInvalidated()) {
                OAuth2Authorization.Token<? extends OAuth2Token> token = (authorization.getRefreshToken() != null) ? authorization.getRefreshToken() : authorization.getAccessToken();
                if(token != null) {
                    authorization = invalidate(authorization, token.getToken());
                    this.authorizationService.save(authorization);
                    System.out.println("Invalidated authorization token(s) previously issued to registered client " + registeredClient.getId());
                }
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        logger.info("Validated token request parameters");

        Authentication principal = authorization.getAttribute(Principal.class.getName());

        String code_challenge = authorizationRequest.getAdditionalParameters().get("code_challenge").toString();
        System.out.println(code_challenge);
        String code_challenge_method = authorizationRequest.getAdditionalParameters().get("code_challenge_method").toString();
        System.out.println(code_challenge_method);
        String code_verifier = authorizationCodeAuthentication.getAdditionalParameters().get("code_verifier").toString();
        System.out.println(code_verifier);

        if (code_challenge == null || code_challenge_method == null || code_verifier == null)
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);

        // Validate PKCE
        if (code_challenge_method.equals("S256")) {
            String code_challenge_calculated;
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] result = sha.digest(code_verifier.getBytes());
                code_challenge_calculated = Base64.getUrlEncoder().encodeToString(result);
            } catch (Exception e) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            if (!Objects.equals(code_challenge_calculated, code_challenge))
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        } else if (code_challenge_method.equals("plain")) {
            if (!Objects.equals(code_verifier, code_challenge))
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        logger.info("Validated the code_verifier.");

        // Validate Authorization Details: if the authorization details are set in the previous request, that should know be also present and be equal
        if(authorization.getAuthorizedScopes().contains("credential") && authorizationRequest.getAdditionalParameters().get("authorization_details") != null) {
            if (authorizationRequest.getAdditionalParameters().get("authorization_details") != null && authorizationCodeAuthentication.getAdditionalParameters().get("authorization_details") == null) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            } else {
                String authDetailsAuthorization = URLDecoder.decode(authorizationRequest.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);
                String authDetailsToken = URLDecoder.decode(authorizationCodeAuthentication.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);
                JSONObject authDetailsAuthorizationJSON = new JSONObject(authDetailsAuthorization);
                JSONObject authDetailsTokenJSON = new JSONObject(authDetailsToken);
                if (!authDetailsAuthorizationJSON.similar(authDetailsTokenJSON)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
                }
            }
            logger.info("Validated Authorization_details");
        }

        logger.info("Token Request is valid.");

        // ----- Access token -----

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
              .registeredClient(registeredClient)
              .principal(principal)
              .authorizationServerContext(AuthorizationServerContextHolder.getContext())
              .authorization(authorization)
              .authorizedScopes(authorization.getAuthorizedScopes())
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrant(authorizationCodeAuthentication)
              .tokenType(OAuth2TokenType.ACCESS_TOKEN);

        if (authorization.getAuthorizedScopes().contains("credential")) {
            System.out.println("here");

            if (authorizationRequest.getAdditionalParameters().get("authorization_details") != null) {
                String authDetailsAuthorization = URLDecoder.decode(authorizationRequest.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);
                JSONObject authDetailsAuthorizationJSON = new JSONObject(authDetailsAuthorization);
                tokenContextBuilder.put("credentialID", authDetailsAuthorizationJSON.get("credentialID"));
                tokenContextBuilder.put("hashAlgorithmOID", authDetailsAuthorizationJSON.get("hashAlgorithmOID"));
                JSONArray documentDigests = authDetailsAuthorizationJSON.getJSONArray("documentDigests");
                List<String> hashesList = new ArrayList<>();
                for (int i = 0; i < documentDigests.length(); i++) {
                    JSONObject document = documentDigests.getJSONObject(i);
                    String hashValue = document.getString("hash");
                    hashesList.add(hashValue);
                }
                String hashes = String.join(",", hashesList);
                tokenContextBuilder.put("numSignatures", documentDigests.length());
                tokenContextBuilder.put("hashes", hashes);
            } else {
                tokenContextBuilder.put("credentialID", authorizationRequest.getAdditionalParameters().get("credentialID").toString());
                tokenContextBuilder.put("numSignatures", authorizationRequest.getAdditionalParameters().get("numSignatures").toString());
                tokenContextBuilder.put("hashes", authorizationRequest.getAdditionalParameters().get("hashes").toString());
                tokenContextBuilder.put("hashAlgorithmOID", authorizationRequest.getAdditionalParameters().get("hashAlgorithmOID").toString());
            }
        }

        DefaultOAuth2TokenContext tokenContext = tokenContextBuilder.build();
        System.out.println("Provider: "+tokenContext.hasKey("credentialID"));

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(), generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        logger.info("Generated access token");

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {

            Map<String, Object> claims = claimAccessor.getClaims();
            for(Map.Entry<String, Object> c: claims.entrySet()){
                System.out.println(c.getKey()+": "+c.getValue());
                System.out.println(c.getValue().getClass());
            }

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
        System.out.println("Saved authorization");

        System.out.println("Authenticated token request");
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
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

}
