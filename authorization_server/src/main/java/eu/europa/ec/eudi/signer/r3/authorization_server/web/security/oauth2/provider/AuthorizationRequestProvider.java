package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.provider;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.ManageOAuth2Authorization;
import java.security.Principal;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
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
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

public class AuthorizationRequestProvider implements AuthenticationProvider {
    private final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = new OAuth2AuthorizationCodeRequestAuthenticationValidator();
    private final RegisteredClientRepository registeredClientRepository;
    private final Logger logger = LogManager.getLogger(AuthorizationRequestProvider.class);
    private final OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
    private final OAuth2AuthorizationService authorizationService;
    private final ManageOAuth2Authorization manageOAuth2Authorization;

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

    public AuthorizationRequestProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, ManageOAuth2Authorization manageOAuth2Authorization) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.manageOAuth2Authorization = manageOAuth2Authorization;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2Error getOAuth2Error(String errorCode, String errorDescription){
        logger.error(errorDescription);
        return new OAuth2Error(errorCode, errorDescription, null);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken =
              (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        logger.info("Authenticating OAuth2AuthorizationCodeRequestAuthenticationToken for the clientID: {}.",
              authenticationToken.getClientId());

        RegisteredClient registeredClient =
              this.registeredClientRepository.findByClientId(authenticationToken.getClientId());
        if (registeredClient == null) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                  "ClientID " + authenticationToken.getClientId() + " from the request not found.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
        }
        logger.info("ClientID from AuthenticationToken is registered.");

        OAuth2AuthorizationCodeRequestAuthenticationContext.Builder authenticationContextBuilder =
              OAuth2AuthorizationCodeRequestAuthenticationContext
                    .with(authenticationToken)
                    .registeredClient(registeredClient);
        this.authenticationValidator.accept(authenticationContextBuilder.build());

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE))
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Request grant_type 'authorization_code' is not allowed for the registered client."), authenticationToken);
        logger.info("Requested grant_type {} for registered client: {}.",
              AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), registeredClient.getId());

        // if the scope requested is in the scopes supported:
        Set<String> requestedScopes = authenticationToken.getScopes();
        if (!CollectionUtils.isEmpty(requestedScopes)) {
            for (String requestedScope : requestedScopes) {
                if (!registeredClient.getScopes().contains(requestedScope))
                    throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE, "The scope "+OAuth2ParameterNames.SCOPE+" is not supported."), authenticationToken);
            }
        }
        logger.info("Validated that the requested scopes are supported scopes.");

        String codeChallenge = (String) authenticationToken
              .getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
        if(!StringUtils.hasText(codeChallenge))
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Error validating the code_challenge & code_challenge_method"), authenticationToken);
        String codeChallengeMethod = (String) authenticationToken
              .getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
        if(!StringUtils.hasText(codeChallengeMethod) || !codeChallengeMethod.equals("S256"))
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Error validating the code_challenge & code_challenge_method. Currently the only code_challenge_method supported is S256."), authenticationToken);
        logger.info("Validated code_challenge & code_challenge_method.");

        String redirectUri = authenticationToken.getRedirectUri();
        if(!StringUtils.hasText(redirectUri)) redirectUri = registeredClient.getRedirectUris().iterator().next();

        // The request is valid - ensure the resource owner is authenticated
        Authentication principal = (Authentication) authenticationToken.getPrincipal();
        if (!isPrincipalAuthenticated(principal)) {
            logger.warn("Did not authenticate authorizationCode request since principal not authenticated");
            return authenticationToken;
        }
        logger.info("Principal of type {} is authenticated.", principal.getClass().getName());

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
              .authorizationUri(authenticationToken.getAuthorizationUri())
              .clientId(registeredClient.getClientId())
              .redirectUri(redirectUri)
              .scopes(requestedScopes)
              .state(authenticationToken.getState())
              .additionalParameters(authenticationToken.getAdditionalParameters())
              .build();
        logger.info("Generated OAuth2AuthorizationRequest: {}.", authorizationRequest.toString());

        OAuth2AuthorizationCode authorizationCode = generateAuthorizationCode(registeredClient, principal,
              requestedScopes, authenticationToken);
        logger.info("Generated OAuth2AuthorizationCode: {}", authorizationCode.getTokenValue());

        System.out.println(principal.getName());
        this.manageOAuth2Authorization.removePreviousOAuth2AuthorizationOfUser(principal.getName(), requestedScopes);

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
              .principalName(principal.getName())
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .attribute(Principal.class.getName(), principal)
              .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
              .authorizedScopes(requestedScopes)
              .token(authorizationCode)
              .build();
        this.authorizationService.save(authorization);
        logger.info("Generated and Saved OAuth2Authorization: {}.", authorization.getId());
        logger.info("Access Token: {}.", authorization.getAccessToken());
        logger.info("Authorization Code: {}.", authorization.getToken(OAuth2AuthorizationCode.class));

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationRequest.getAuthorizationUri(),
              registeredClient.getClientId(), principal, authorizationCode, redirectUri, authorizationRequest.getState(), requestedScopes);
    }

    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) && principal.isAuthenticated();
    }

    // Generate the authorization code
    private OAuth2AuthorizationCode generateAuthorizationCode(RegisteredClient registeredClient, Authentication principal,
                                                              Set<String> requestedScopes, OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken){

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
              .registeredClient(registeredClient)
              .principal(principal)
              .authorizationServerContext(AuthorizationServerContextHolder.getContext())
              .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
              .authorizedScopes(requestedScopes)
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrant(authenticationToken);
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();

        System.out.println("Equals Access_token?: "+ tokenContext.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN));

        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null)
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the authorization code."), null);

        return authorizationCode;
    }
}
