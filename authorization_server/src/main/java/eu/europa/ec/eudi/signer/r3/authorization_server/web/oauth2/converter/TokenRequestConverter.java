package eu.europa.ec.eudi.signer.r3.authorization_server.web.oauth2.converter;

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

public class TokenRequestConverter implements AuthenticationConverter {

    private final RequestMatcher tokenRequestMatcher;
    private final Logger logger = LogManager.getLogger(TokenRequestConverter.class);

    public TokenRequestConverter(){
        RequestMatcher tokenRequestMatcher = OAuth2TokenRequest.requestMatcher();
        this.tokenRequestMatcher = new AndRequestMatcher(
              new AntPathRequestMatcher(
                    "/oauth2/token", HttpMethod.POST.name()
              ), tokenRequestMatcher
        );
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        System.out.println("Request @"+request.getRequestURL().toString());

        if(!this.tokenRequestMatcher.matches(request)){
            String errorType = "invalid_request";
            String error_description = "The request doesn't match the requests supported. Possible parameters missing.";
            logger.warn(error_description);
            OAuth2Error error = new OAuth2Error(errorType, error_description, null);
            throw new OAuth2AuthenticationException(error);
        }
        logger.info("The Token Request match the 'request matcher'.");

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.from(request);

        // grant_type (REQUIRED)
        String grantType = tokenRequest.getGrant_type();
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
            String errorType = "invalid_request";
            String error_description = "The grant type requested is not supported.";
            logger.warn(error_description + "{"+grantType+"}");
            OAuth2Error error = new OAuth2Error(errorType, error_description, null);
            throw new OAuth2AuthenticationException(error);
        }
        logger.info("Grant_type: "+grantType);

        // code (REQUIRED)
        String code = tokenRequest.getCode();
        if (!StringUtils.hasText(code) || request.getParameterValues("code").length != 1) {
            String errorType = "invalid_request";
            String error_description = "The code parameter is required.";
            logger.warn(error_description);
            OAuth2Error error = new OAuth2Error(errorType, error_description, null);
            throw new OAuth2AuthenticationException(error);
        }
        logger.info("Code: "+ code);

        // redirect_uri (REQUIRED)
        String redirectUri = tokenRequest.getRedirect_uri();
        if (StringUtils.hasText(redirectUri) && request.getParameterValues(OAuth2ParameterNames.REDIRECT_URI).length != 1) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: " +  OAuth2ParameterNames.REDIRECT_URI,  "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
            throw new OAuth2AuthenticationException(error);
        }
        logger.info("Redirect Uri: "+redirectUri);

        Map<String, Object> additionalParameters = new HashMap<>();
        Enumeration<String> params = request.getParameterNames();
        while (params.hasMoreElements()){
            String param = params.nextElement();
            if(!Objects.equals(param, "code")
                  && !Objects.equals(param, "grant_type")
                  && !Objects.equals(param, "redirect_uri"))
                additionalParameters.put(param, request.getParameter(param));
        }
        return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri, additionalParameters);
    }
}
