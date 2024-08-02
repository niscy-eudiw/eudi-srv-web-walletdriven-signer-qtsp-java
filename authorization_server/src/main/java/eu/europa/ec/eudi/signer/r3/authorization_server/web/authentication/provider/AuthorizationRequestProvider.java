// https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/authentication/OAuth2AuthorizationCodeRequestAuthenticationProvider.java

package eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.provider;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OID4VPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.AuthorizationRequestVariables;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.tokens.Oid4vpAuthorizationRequestToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.Set;

/**
 * A main processor used for authenticating the OAuth2AuthorizationCodeRequestAuthenticationToken
 */
public class AuthorizationRequestProvider implements AuthenticationProvider {

    private final OID4VPService oid4VPService;
    private final RegisteredClientRepository registeredClientRepository;
    private final Logger logger = LogManager.getLogger(AuthorizationRequestProvider.class);

    public AuthorizationRequestProvider(RegisteredClientRepository registeredClientRepository, OID4VPService oid4VPService) {
        this.registeredClientRepository = registeredClientRepository;
        this.oid4VPService = oid4VPService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2Error getOAuth2Error(String errorCode, String errorDescription){
        System.out.println(errorDescription);
        return new OAuth2Error(errorCode, errorDescription, null);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        logger.info("authenticate Authentication Token from clientID: {}", authenticationToken.getClientId());

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(authenticationToken.getClientId());
        if (registeredClient == null) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "ClientID "+ authenticationToken.getClientId() +" not found.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
        logger.info("clientID from Authentication Token is registered");

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Request grant_type is not allowed for the registered client.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
        logger.info("Requested grant_type {} for registered client: {}", AuthorizationGrantType.AUTHORIZATION_CODE, registeredClient.getId());

        // if the scope requested is in the scopes supported:
        Set<String> requestedScopes = authenticationToken.getScopes();
        if (!CollectionUtils.isEmpty(requestedScopes)) {
            for (String requestedScope : requestedScopes) {
                if (!registeredClient.getScopes().contains(requestedScope)) {
                    getOAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE);
                }
            }
        }

        String codeChallengeMethod = "plain";
        String codeChallenge = (String) authenticationToken.getAdditionalParameters().get("code_challenge");
        if (StringUtils.hasText(codeChallenge)) {
            codeChallengeMethod = (String) authenticationToken.getAdditionalParameters().get("code_challenge_method");
            if (!StringUtils.hasText(codeChallengeMethod) || !"S256".equals(codeChallengeMethod)) {
                OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Error validating the code_challenge & code_challenge_method");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
            }
        }
        logger.info("Validated code_challenge & code_challenge_method.");

        // The request is valid - ensure the resource owner is authenticated
        Authentication principal = (Authentication) authenticationToken.getPrincipal();
        if (!isPrincipalAuthenticated(principal)) {
            System.out.println("Did not authenticate authorization code request since principal not authenticated");
            // return authenticationToken;
        }

        String scope = "service";
        String service_url = "http://localhost:9000" ;
        if(scope.equals("credential")){
            service_url = "http://localhost:9000";
        }
        else if (scope.equals("service")){
            service_url = "http://localhost:9000";
        }

        AuthorizationRequestVariables variables =  this.oid4VPService.authorizationRequest("some_user", service_url);
        return new Oid4vpAuthorizationRequestToken(variables.getRedirectLink());
    }

    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) && principal.isAuthenticated();
    }

}
