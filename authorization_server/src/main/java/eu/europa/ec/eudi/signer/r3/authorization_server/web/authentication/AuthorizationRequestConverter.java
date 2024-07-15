package eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication;

import eu.europa.ec.eudi.signer.r3.authorization_server.authentication.AuthorizationCodeRequestAuthenticationToken;
import eu.europa.ec.eudi.signer.r3.authorization_server.oid4vp.dto.OAuth2AuthorizeRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.*;

public class AuthorizationRequestConverter implements AuthenticationConverter {

    private final RequestMatcher authenticationServiceRequestMatcher;
    private final RequestMatcher authorizationCredentialRequestMatcher;

    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
        "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

    public AuthorizationRequestConverter(){
        RequestMatcher requestMatcher = request ->
            request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null;

        this.authenticationServiceRequestMatcher = new AndRequestMatcher(
            new AntPathRequestMatcher(
                "/oauth2/authorize", HttpMethod.GET.name()
            ), requestMatcher
        );

        this.authorizationCredentialRequestMatcher = new AndRequestMatcher(
            new AntPathRequestMatcher(
                "/oauth2/authorize", HttpMethod.GET.name()
            ), requestMatcher
        );

    }

    // TODO: Authentication Principal and Authorization URI
    @Override
    public Authentication convert(HttpServletRequest request){
        System.out.println(request.getRequestURL().toString());
        if(!this.authenticationServiceRequestMatcher.matches(request) && !this.authorizationCredentialRequestMatcher.matches(request)){
            System.out.println("here 1");
            return null;
        }

        Enumeration<String> params = request.getParameterNames();
        while (params.hasMoreElements()){
            System.out.println(params.nextElement());
        }

        try{
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(request);
            Map<String, Object> additionalParameters = new HashMap<>();
            additionalParameters.put("code_challenge", authorizeRequest.getCode_challenge());
            additionalParameters.put("code_challenge_method", authorizeRequest.getCode_challenge_method());
            Set<String> scopes = new HashSet<>();
            scopes.add(authorizeRequest.getScope());

            Authentication principal = SecurityContextHolder.getContext().getAuthentication();
            if (principal == null) {



                principal = ANONYMOUS_AUTHENTICATION;
                System.out.println("Authentication Principal not defined.");
            }

            return new AuthorizationCodeRequestAuthenticationToken(
                request.getRequestURL().toString(),
                authorizeRequest.getClient_id(),
                principal,
                authorizeRequest.getRedirect_uri(),
                authorizeRequest.getState(),
                scopes,
                additionalParameters
            );
        }
        catch (Exception e){
            e.printStackTrace();
            System.out.println("here 4: "+ e.getMessage());
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: " +  OAuth2ParameterNames.CLIENT_ID, DEFAULT_ERROR_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
    }
}
