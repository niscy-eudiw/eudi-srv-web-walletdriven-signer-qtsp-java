package eu.europa.ec.eudi.signer.r3.authorization_server.web.oauth2.provider;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

public class TokenRequestProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    private final OAuth2AuthorizationService authorizationService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private SessionRegistry sessionRegistry;

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
        logger.info("Retrieved registered client: "+registeredClient.getClientId());

        // Get the Authorization Request Information
        OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCodeAuthentication.getCode(), AUTHORIZATION_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        logger.info("Retrieved authorization with authorization code: "+authorization.getToken(OAuth2AuthorizationCode.class));
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

        // verifies that the client that requested the code is the same to the one requesting the access token
        if (!registeredClient.getClientId().equals(authorizationRequest.getClientId())) {
            if (!authorizationCode.isInvalidated()) {
                authorization = invalidate(authorization,
                      authorizationCode.getToken());
                this.authorizationService.save(authorization);
                System.out.println(LogMessage.format("Invalidated authorization code used by registered client '%s'", registeredClient.getId()));
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // Validates that the redirect uri in the token request is equal to the one in the authorization request
        if (StringUtils.hasText(authorizationRequest.getRedirectUri())  && !authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
            System.out.println(LogMessage.format("Invalid request: redirect_uri does not match" + " for registered client '%s'", registeredClient.getClientId()));
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (!authorizationCode.isActive()) {
            if (authorizationCode.isInvalidated()) {
                OAuth2Authorization.Token<? extends OAuth2Token> token = (authorization.getRefreshToken() != null)? authorization.getRefreshToken() : authorization.getAccessToken();
                if (token != null) {
                    authorization =  invalidate(authorization, token.getToken());
                    this.authorizationService.save(authorization);
                    System.out.println("Invalidated authorization token(s) previously issued to registered client " + registeredClient.getId());
                }
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        System.out.println("Validated token request parameters");

        Authentication principal = authorization.getAttribute(Principal.class.getName());

        String code_challenge = authorizationRequest.getAttribute("code_challenge");
        String code_challenge_method = authorizationRequest.getAttribute("code_challenge_method");
        String code_verifier = authorizationCodeAuthentication.getAdditionalParameters().get("code_verifier").toString();

        if(code_challenge == null || code_challenge_method == null || code_verifier == null)
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);

        // Validate PKCE
        if(code_challenge_method.equals("S256")){
            String code_challenge_calculated;
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] result = sha.digest(code_verifier.getBytes());
                code_challenge_calculated = Base64.getUrlEncoder().encodeToString(result);
            }
            catch (Exception e){
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            if(!Objects.equals(code_challenge_calculated, code_challenge))
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        else if(authorizationRequest.getAttribute("code_challenge_method").equals("plain")){
            if(!Objects.equals(code_verifier, code_challenge))
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        logger.info("Validated the code_verifier.");


        // Validate Authorization Details: if the authorization details are set in the previous request, that should know be also present and be equal
        if(authorizationRequest.getAdditionalParameters().get("authorization_details") != null && authorizationCodeAuthentication.getAdditionalParameters().get("authorization_details") == null){
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        else{
            String authDetailsAuthorization = URLDecoder.decode(authorizationRequest.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8) ;
            String authDetailsToken = URLDecoder.decode(authorizationCodeAuthentication.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);
            JSONObject authDetailsAuthorizationJSON = new JSONObject(authDetailsAuthorization);
            JSONObject authDetailsTokenJSON = new JSONObject(authDetailsToken);
            if(!authDetailsAuthorizationJSON.similar(authDetailsTokenJSON)){
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
        }
        logger.info("Validated Authorization_details");

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
              .registeredClient(registeredClient)
              .principal(principal)
              .authorizationServerContext(AuthorizationServerContextHolder.getContext())
              .authorization(authorization)
              .authorizedScopes(authorization.getAuthorizedScopes())
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrant(authorizationCodeAuthentication);
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

        // ----- Access token -----
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }
        System.out.println("Generated access token");

        OAuth2AccessToken accessToken = accessToken(authorizationBuilder, generatedAccessToken, tokenContext);

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;
        // Do not issue refresh token to public client
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (generatedRefreshToken != null) {
                if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                    OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                          "The token generator failed to generate a valid refresh token.", ERROR_URI);
                    throw new OAuth2AuthenticationException(error);
                }

                System.out.println("Generated refresh token");

                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                authorizationBuilder.refreshToken(refreshToken);
            }
        }

        authorization = authorizationBuilder.build();

        // Invalidate the authorization code as it can only be used once
        authorization = invalidate(authorization, authorizationCode.getToken());
        this.authorizationService.save(authorization);
        System.out.println("Saved authorization");

        Map<String, Object> additionalParameters = Collections.emptyMap();
        System.out.println("Authenticated token request");

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Sets the {@link SessionRegistry} used to track OpenID Connect sessions.
     * @param sessionRegistry the {@link SessionRegistry} used to track OpenID Connect
     * sessions
     * @since 1.1
     */
    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
        this.sessionRegistry = sessionRegistry;
    }

    private SessionInformation getSessionInformation(Authentication principal) {
        SessionInformation sessionInformation = null;
        if (this.sessionRegistry != null) {
            List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal.getPrincipal(), false);
            if (!CollectionUtils.isEmpty(sessions)) {
                sessionInformation = sessions.get(0);
                if (sessions.size() > 1) {
                    // Get the most recent session
                    sessions = new ArrayList<>(sessions);
                    sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
                    sessionInformation = sessions.get(sessions.size() - 1);
                }
            }
        }
        return sessionInformation;
    }

    private static String createHash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
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

    private static <T extends OAuth2Token> OAuth2AccessToken accessToken(OAuth2Authorization.Builder builder, T token,
                                                                 OAuth2TokenContext accessTokenContext) {

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token.getTokenValue(),
              token.getIssuedAt(), token.getExpiresAt(), accessTokenContext.getAuthorizedScopes());
        OAuth2TokenFormat accessTokenFormat = accessTokenContext.getRegisteredClient()
              .getTokenSettings()
              .getAccessTokenFormat();
        builder.token(accessToken, (metadata) -> {
            if (token instanceof ClaimAccessor claimAccessor) {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
            }
            metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
            metadata.put(OAuth2TokenFormat.class.getName(), accessTokenFormat.getValue());
        });

        return accessToken;
    }
}
