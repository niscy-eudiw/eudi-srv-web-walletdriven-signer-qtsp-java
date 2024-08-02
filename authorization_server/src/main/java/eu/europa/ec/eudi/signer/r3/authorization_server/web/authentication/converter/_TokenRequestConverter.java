package eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.converter;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2TokenRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.*;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

public class _TokenRequestConverter implements AuthenticationConverter {

    private final RequestMatcher tokenRequestMatcher;
    private final Logger logger = LogManager.getLogger(_TokenRequestConverter.class);

    public _TokenRequestConverter(){
        RequestMatcher tokenRequestMatcher = OAuth2TokenRequest.requestMatcher();
        this.tokenRequestMatcher = new AndRequestMatcher(
              new AntPathRequestMatcher(
                    "/oauth2/token", HttpMethod.POST.name()
              ), tokenRequestMatcher
        );
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        System.out.println(request.getRequestURL().toString());

        System.out.println(request.getParameter("grant_type"));
        System.out.println(request.getParameter("code"));
        System.out.println(request.getParameter("redirect_uri"));

        if(!this.tokenRequestMatcher.matches(request)){
            String errorType = "invalid_request";
            String error_description = "The request doesn't match the requests supported. Possible parameters missing.";
            logger.warn(error_description);
            OAuth2Error error = new OAuth2Error(errorType, error_description, null);
            throw new OAuth2AuthenticationException(error);
        }
        logger.info("The Token Request match the 'request matcher'.");

        // grant_type (REQUIRED)
        String grantType = request.getParameter("grant_type");
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
            String errorType = "invalid_request";
            String error_description = "The grant type requested is not supported.";
            logger.warn(error_description + "{"+grantType+"}");
            OAuth2Error error = new OAuth2Error(errorType, error_description, null);
            throw new OAuth2AuthenticationException(error);
        }
        logger.info(grantType+ " is valid.");

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // code (REQUIRED)
        String code = request.getParameter("code");
        if (!StringUtils.hasText(code) || request.getParameterValues("code").length != 1) {
            String errorType = "invalid_request";
            String error_description = "The code parameter is required.";
            logger.warn(error_description);
            OAuth2Error error = new OAuth2Error(errorType, error_description, null);
            throw new OAuth2AuthenticationException(error);
        }
        logger.info("Code parameter is presented: "+ code);

        // redirect_uri (REQUIRED)
        // Required only if the "redirect_uri" parameter was included in the authorization request
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.hasText(redirectUri) && request.getParameterValues(OAuth2ParameterNames.REDIRECT_URI).length != 1) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: " +  OAuth2ParameterNames.REDIRECT_URI,  "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
            throw new OAuth2AuthenticationException(error);
        }
        System.out.println(redirectUri);

        Map<String, Object> additionalParameters = new HashMap<>();

        Enumeration<String> params = request.getParameterNames();
        while (params.hasMoreElements()){
            String param = params.nextElement();
            System.out.println(param);
            if(!Objects.equals(param, "code")
                  && !Objects.equals(param, "grant_type")
                  && !Objects.equals(param, "redirect_uri"))
                additionalParameters.put(param, request.getParameter(param));
        }
        System.out.println("here");
        return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri, additionalParameters);
    }
}
