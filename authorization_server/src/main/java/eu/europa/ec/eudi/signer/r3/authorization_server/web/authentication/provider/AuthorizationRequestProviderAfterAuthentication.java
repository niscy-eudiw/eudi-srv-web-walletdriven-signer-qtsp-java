package eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.provider;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.tokens.Oid4vpAuthorizationResponseToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
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
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.time.Instant;
import java.util.Base64;
import java.util.function.Consumer;

public class AuthorizationRequestProviderAfterAuthentication implements AuthenticationProvider {

    private final RegisteredClientRepository registeredClientRepository;
    private final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = new OAuth2AuthorizationCodeRequestAuthenticationValidator();
    private final OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
    private final OAuth2AuthorizationService authorizationService;
    private final Logger logger = LogManager.getLogger(AuthorizationRequestProviderAfterAuthentication.class);
    private final AuthorizationServerContext serverContext;

    private static class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {

        private final StringKeyGenerator authorizationCodeGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

        @Nullable
        @Override
        public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
            if (context.getTokenType() == null || !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
            return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
        }
    }

    public AuthorizationRequestProviderAfterAuthentication(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, AuthorizationServerContext context) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.serverContext = context;
    }

    private OAuth2Error getOAuth2Error(String errorCode, String errorDescription){
        System.out.println(errorDescription);
        return new OAuth2Error(errorCode, errorDescription, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication){
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        logger.info("authenticate Authentication Token from clientID: {}", authenticationToken.getClientId());

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(authenticationToken.getClientId());
        if (registeredClient == null) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "ClientID "+ authenticationToken.getClientId() +" not found.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
        logger.info("clientID from Authentication Token is registered");

        String codeChallengeMethod = "S256";
        String codeChallenge = (String) authenticationToken.getAdditionalParameters().get("code_challenge");
        codeChallenge = "some_nonce_2";
        if (StringUtils.hasText(codeChallenge)) {
            // codeChallengeMethod = (String) authenticationToken.getAdditionalParameters().get("code_challenge_method");
            if (!StringUtils.hasText(codeChallengeMethod) || !"S256".equals(codeChallengeMethod)) {
                OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Error validating the code_challenge & code_challenge_method");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
            }
        }
        logger.info("Validated code_challenge & code_challenge_method.");

        String redirectUri = authenticationToken.getRedirectUri();
        if (!StringUtils.hasText(redirectUri)) {
            redirectUri = registeredClient.getRedirectUris().iterator().next();
        }

        Authentication principal = (Authentication) authenticationToken.getPrincipal();

        OAuth2AuthorizationCodeRequestAuthenticationContext.Builder authenticationContextBuilder =
              OAuth2AuthorizationCodeRequestAuthenticationContext.with(authenticationToken).registeredClient(registeredClient);
        this.authenticationValidator.accept(authenticationContextBuilder.build());

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
              .authorizationUri(authenticationToken.getAuthorizationUri())
              .clientId(registeredClient.getClientId())
              .redirectUri(authenticationToken.getRedirectUri())
              .scopes(authenticationToken.getScopes())
              .state(authenticationToken.getState())
              .additionalParameters(authenticationToken.getAdditionalParameters())
              .build();
        authenticationContextBuilder.authorizationRequest(authorizationRequest);

        OAuth2AuthorizationCode authorizationCode = generateAuthorizationCode(registeredClient, principal, authenticationToken);
        savesAuthorization(registeredClient, principal, authorizationRequest, codeChallenge, codeChallengeMethod, authenticationToken, authorizationCode);

        return new Oid4vpAuthorizationResponseToken(
              principal,
              authorizationCode,
              redirectUri,
              authorizationRequest.getState());
    }

    // Generate the authorization code
    private OAuth2AuthorizationCode generateAuthorizationCode(RegisteredClient registeredClient, Authentication principal, OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken){
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
              .registeredClient(registeredClient)
              .principal(principal)
              .authorizationServerContext(this.serverContext)
              .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
              .authorizedScopes(authenticationToken.getScopes())
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrant(authenticationToken);
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the authorization code.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
        logger.info("Generated authorization code: {}", authorizationCode.getTokenValue());
        return authorizationCode;
    }

    // saves authorization data in the authorization service for later verify
    private void savesAuthorization(
          RegisteredClient registeredClient,
          Authentication principal,
          OAuth2AuthorizationRequest authorizationRequest,
          String codeChallenge,
          String codeChallengeMethod,
          OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken,
          OAuth2AuthorizationCode authorizationCode)
    {
        OAuth2Authorization authorization =
              OAuth2Authorization.withRegisteredClient(registeredClient)
                    .principalName(principal.getName())
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .attribute(Principal.class.getName(), principal)
                    .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                    .attribute("code_challenge", codeChallenge)
                    .attribute("code_challenge_method", codeChallengeMethod)
                    .authorizedScopes(authenticationToken.getScopes())
                    .token(authorizationCode)
                    .build();
        this.authorizationService.save(authorization);
    }
}
