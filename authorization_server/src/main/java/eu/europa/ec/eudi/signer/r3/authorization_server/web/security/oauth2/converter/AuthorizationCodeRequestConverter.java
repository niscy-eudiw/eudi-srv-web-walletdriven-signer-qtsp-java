package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.converter;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.AuthenticationManagerToken;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * A Pre-processor used when attempting to extract an OAuth2 Authorization Request
 * from a HttpServletRequest to an instance of OAuth2AuthorizationCodeRequestAuthenticationToken.
 */
public class AuthorizationCodeRequestConverter implements AuthenticationConverter {

    private final RequestMatcher authenticationServiceRequestMatcher;
    private final RequestMatcher authorizationCredentialRequestMatcher;
    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final Logger logger = LogManager.getLogger(AuthorizationCodeRequestConverter.class);

    public AuthorizationCodeRequestConverter(){
        RequestMatcher serviceRequestMatcher = OAuth2AuthorizeRequest.requestMatcherForService();
        this.authenticationServiceRequestMatcher = new AndRequestMatcher(
            new AntPathRequestMatcher(
                "/oauth2/authorize", HttpMethod.GET.name()
            ), serviceRequestMatcher
        );

        RequestMatcher credentialsRequestMatcher = OAuth2AuthorizeRequest.requestMatcherForCredential();
        this.authorizationCredentialRequestMatcher = new AndRequestMatcher(
            new AntPathRequestMatcher(
                "/oauth2/authorize", HttpMethod.GET.name()
            ), credentialsRequestMatcher
        );
    }

    @Override
    public Authentication convert(HttpServletRequest request){
        logger.info("Request received at {}", request.getRequestURL().toString());

        if(!this.authenticationServiceRequestMatcher.matches(request) && !this.authorizationCredentialRequestMatcher.matches(request)){
            if(!request.getParameter("response_type").equals("code")){
                String error_description = "The response type in the request is not supported.";
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, error_description, null);
                logger.error(error.toString());
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
            }
            else {
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
        Set<String> scopes = new HashSet<>();
        if(authorizeRequest.getScope() == null && authorizeRequest.getAuthorization_details() != null)
            scopes.add("credential");
        else
            scopes.add(authorizeRequest.getScope());

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            principal = ANONYMOUS_AUTHENTICATION;
            logger.warn("Authentication is not present. The user is not authenticated.");
        }
        else if (!principal.getClass().equals(AuthenticationManagerToken.class) && !principal.getClass().equals(UsernamePasswordAuthenticationToken.class)) {
            principal = ANONYMOUS_AUTHENTICATION;
            logger.warn("Authentication present is not valid. The authentication mechanism is not the supported.");
        }
        else if(principal.getClass().equals(AuthenticationManagerToken.class)){
            logger.info("Authentication Principal is a AuthenticationManagerToken.");
            AuthenticationManagerToken token = (AuthenticationManagerToken) principal;
            if(scopes.contains("credential") && !Objects.equals(token.getScope(), "credential")){
                logger.warn("For the credential scope, the Authentication should have been performed for an credential scope.");
                principal = ANONYMOUS_AUTHENTICATION;
            }
        }
        logger.info("Principal present: {}", principal);

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationToken =
              new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getRequestURL().toString(),
                    authorizeRequest.getClient_id(), principal, authorizeRequest.getRedirect_uri(),
                    authorizeRequest.getState(), scopes, additionalParameters);

        logger.info("OAuth2AuthorizationCodeRequestAuthenticationToken is generated.");
        return authorizationCodeRequestAuthenticationToken;
    }

    private static Map<String, Object> getAdditionalParameters(OAuth2AuthorizeRequest authorizeRequest) {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("authorization_details", authorizeRequest.getAuthorization_details());
        additionalParameters.put("code_challenge", authorizeRequest.getCode_challenge());
        additionalParameters.put("code_challenge_method", authorizeRequest.getCode_challenge_method());
        additionalParameters.put("lang", authorizeRequest.getLang());
        additionalParameters.put("credentialID", authorizeRequest.getCredentialID());
        additionalParameters.put("signatureQualifier", authorizeRequest.getSignatureQualifier());
        additionalParameters.put("numSignatures", authorizeRequest.getNumSignatures());
        additionalParameters.put("hashes", authorizeRequest.getHashes());
        additionalParameters.put("hashAlgorithmOID", authorizeRequest.getHashAlgorithmOID());
        additionalParameters.put("description", authorizeRequest.getDescription());
        additionalParameters.put("account_token", authorizeRequest.getAccount_token());
        additionalParameters.put("clientData", authorizeRequest.getClientData());

        return additionalParameters;
    }
}
