// https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/authentication/OAuth2AuthorizationCodeRequestAuthenticationProvider.java

package eu.europa.ec.eudi.signer.r3.authorization_server.authentication;

import org.springframework.lang.Nullable;
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
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.function.Consumer;



public class AuthorizationRequestProvider implements AuthenticationProvider {

    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    private final RegisteredClientRepository registeredClientRepository;
    private final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = new OAuth2AuthorizationCodeRequestAuthenticationValidator();
    private final OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
    private final OAuth2AuthorizationService authorizationService;

    private static class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {

        private final StringKeyGenerator authorizationCodeGenerator = new Base64StringKeyGenerator(
            Base64.getUrlEncoder().withoutPadding(), 96);

        @Nullable
        @Override
        public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
            if (context.getTokenType() == null || !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt
                .plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
            return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
        }
    }


    public AuthorizationRequestProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AuthorizationCodeRequestAuthenticationToken authenticationToken = (AuthorizationCodeRequestAuthenticationToken) authentication;
        System.out.println("Client ID in the Authentication Token: " + authenticationToken.getClientId());

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(authenticationToken.getClientId());
        if (registeredClient == null) {
            System.out.println("ClientID "+ authenticationToken.getClientId()+ " not found.");
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: " +  OAuth2ParameterNames.CLIENT_ID, DEFAULT_ERROR_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
        System.out.println("ClientID "+ authenticationToken.getClientId()+ " found.");

        OAuth2AuthorizationCodeRequestAuthenticationContext.Builder authenticationContextBuilder;
        try{
            authenticationContextBuilder = OAuth2AuthorizationCodeRequestAuthenticationContext.with(authenticationToken).registeredClient(registeredClient);
            this.authenticationValidator.accept(authenticationContextBuilder.build());
        }catch (AuthenticationException e){
            e.printStackTrace();
            throw e;
        }

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            System.out.println("Invalid request: requested grant_type is not allowed for registered client " +  registeredClient.getId());
        }
        System.out.println("Requested grant_type "+AuthorizationGrantType.AUTHORIZATION_CODE+" for registered client: " +  registeredClient.getId());

        // code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
        String codeChallenge = (String) authenticationToken.getAdditionalParameters()
            .get(PkceParameterNames.CODE_CHALLENGE);
        if (StringUtils.hasText(codeChallenge)) {
            String codeChallengeMethod = (String) authenticationToken.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
            if (!StringUtils.hasText(codeChallengeMethod) || !"S256".equals(codeChallengeMethod)) {
                System.out.println("Error validating the code_challenge & code_challenge_method.");
            }
        }
        System.out.println("Validated code_challenge & code_challenge_method.");

        // ---------------
        // The request is valid - ensure the resource owner is authenticated
        // ---------------

        Authentication principal = (Authentication) authenticationToken.getPrincipal();
        if (!isPrincipalAuthenticated(principal)) {
            System.out.println("Did not authenticate authorization code request since principal not authenticated");
            return authenticationToken;
        }

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri(authenticationToken.getAuthorizationUri())
            .clientId(registeredClient.getClientId())
            .redirectUri(authenticationToken.getRedirectUri())
            .scopes(authenticationToken.getScopes())
            .state(authenticationToken.getState())
            .additionalParameters(authenticationToken.getAdditionalParameters())
            .build();
        authenticationContextBuilder.authorizationRequest(authorizationRequest);

        /*OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService
            .findById(registeredClient.getId(), principal.getName());
        if (currentAuthorizationConsent != null) {
            authenticationContextBuilder.authorizationConsent(currentAuthorizationConsent);
        }*/

        /*if (this.authorizationConsentRequired.test(authenticationContextBuilder.build())) {
            String state = DEFAULT_STATE_GENERATOR.generateKey();
            OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
                .attribute(OAuth2ParameterNames.STATE, state)
                .build();

            System.out.println("Generated authorization consent state");


            this.authorizationService.save(authorization);

            Set<String> currentAuthorizedScopes = (currentAuthorizationConsent != null)
                ? currentAuthorizationConsent.getScopes() : null;

            System.out.println("Saved authorization");

            return new OAuth2AuthorizationConsentAuthenticationToken(authorizationRequest.getAuthorizationUri(),
                registeredClient.getClientId(), principal, state, currentAuthorizedScopes, null);
        }*/

        OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(authenticationToken,
            registeredClient, null, authorizationRequest.getScopes());
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the authorization code.", DEFAULT_ERROR_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }

        System.out.println("Generated authorization code");


        OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
            .authorizedScopes(authorizationRequest.getScopes())
            .token(authorizationCode)
            .build();
        this.authorizationService.save(authorization);

        System.out.println("Saved authorization");

        String redirectUri = authorizationRequest.getRedirectUri();
        if (!StringUtils.hasText(redirectUri)) {
            redirectUri = registeredClient.getRedirectUris().iterator().next();
        }

        System.out.println("Authenticated authorization code request");

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationRequest.getAuthorizationUri(),
            registeredClient.getClientId(), principal, authorizationCode, redirectUri,
            authorizationRequest.getState(), authorizationRequest.getScopes());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return true;
        // return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) && principal.isAuthenticated();
    }

    private static OAuth2TokenContext createAuthorizationCodeTokenContext(
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
        RegisteredClient registeredClient, OAuth2Authorization authorization, Set<String> authorizedScopes) {

        // @formatter:off
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal((Authentication) authorizationCodeRequestAuthentication.getPrincipal())
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
            .authorizedScopes(authorizedScopes)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrant(authorizationCodeRequestAuthentication);
        // @formatter:on

        if (authorization != null) {
            tokenContextBuilder.authorization(authorization);
        }

        return tokenContextBuilder.build();
    }

    private static OAuth2Authorization.Builder authorizationBuilder(RegisteredClient registeredClient,
                                                                    Authentication principal, OAuth2AuthorizationRequest authorizationRequest) {
        return OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(principal.getName())
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .attribute(Principal.class.getName(), principal)
            .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
    }
}
