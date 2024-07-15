package eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

public class TokenRequestConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        System.out.println("here");

        Enumeration<String> params = request.getParameterNames();
        while (params.hasMoreElements()){
            System.out.println(params.nextElement());
        }

        // grant_type (REQUIRED)
        String grantType = request.getParameter("grant_type");
        System.out.println(grantType);

        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
            return null;
        }

        System.out.println("here2");

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // code (REQUIRED)
        String code = request.getParameter("code");
        if (!StringUtils.hasText(code) || request.getParameterValues("code").length != 1) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: " +  OAuth2ParameterNames.CODE,  "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
            throw new OAuth2AuthenticationException(error);
        }

        System.out.println(code);

        // redirect_uri (REQUIRED)
        // Required only if the "redirect_uri" parameter was included in the authorization
        // request
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.hasText(redirectUri) && request.getParameterValues(OAuth2ParameterNames.REDIRECT_URI).length != 1) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: " +  OAuth2ParameterNames.REDIRECT_URI,  "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
            throw new OAuth2AuthenticationException(error);
        }

        System.out.println(redirectUri);

        Map<String, Object> additionalParameters = new HashMap<>();
        return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri, additionalParameters);
    }

    private MultiValueMap<String, String> getFormParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            // If not query parameter then it's a form parameter
            if (!queryString.contains(key) && values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }
}
