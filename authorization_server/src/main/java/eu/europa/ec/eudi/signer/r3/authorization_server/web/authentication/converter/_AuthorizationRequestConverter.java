package eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.converter;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2AuthorizeRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;


/**
 * A Pre-processor used when attempting to extract an OAuth2 Authorization Request
 * from a HttpServletRequest to an instance of OAuth2AuthorizationCodeRequestAuthenticationToken.
 */
public class _AuthorizationRequestConverter implements AuthenticationConverter {

    private final RequestMatcher authenticationServiceRequestMatcher;
    private final RequestMatcher authorizationCredentialRequestMatcher;
    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

    public _AuthorizationRequestConverter(){
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

        AuthorizationServerContext serverContext = AuthorizationServerContextHolder.getContext();
        System.out.println(serverContext.getAuthorizationServerSettings());
        System.out.println(serverContext.issuer());

        System.out.println(request.getRequestURL().toString());
        if(!this.authenticationServiceRequestMatcher.matches(request) && !this.authorizationCredentialRequestMatcher.matches(request)){
            String errorType = "invalid_request";
            String error_description = "The request doesn't match the requests supported. Possible parameters missing.";
            System.out.println(error_description);
            OAuth2Error error = new OAuth2Error(errorType, error_description, null);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }

        try{
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(request);
            Map<String, Object> additionalParameters = getAdditionalParameters(authorizeRequest);
            Set<String> scopes = new HashSet<>();
            scopes.add(authorizeRequest.getScope());

            Authentication principal = SecurityContextHolder.getContext().getAuthentication();
            if (principal == null) {
                principal = ANONYMOUS_AUTHENTICATION;
                System.out.println("Authentication Principal not defined.");
            }

            return new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getRequestURL().toString(),
                  authorizeRequest.getClient_id(), principal, authorizeRequest.getRedirect_uri(),
                  authorizeRequest.getState(), scopes, additionalParameters);
        }
        catch (Exception e){
            e.printStackTrace();
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Unexpected Error", null);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
    }

    private static Map<String, Object> getAdditionalParameters(OAuth2AuthorizeRequest authorizeRequest) {
        Map<String, Object> additionalParameters = new HashMap<>();

        additionalParameters.put("code_challenge", authorizeRequest.getCode_challenge());
        additionalParameters.put("code_challenge_method", authorizeRequest.getCode_challenge_method());
        additionalParameters.put("credentialID", authorizeRequest.getCredentialID());
        additionalParameters.put("signatureQualifier", authorizeRequest.getSignatureQualifier());
        additionalParameters.put("numSignatures", authorizeRequest.getNumSignatures());
        additionalParameters.put("hashes", authorizeRequest.getHashes());
        additionalParameters.put("hashAlgorithmOID", authorizeRequest.getHashAlgorithmOID());
        return additionalParameters;
    }
}
