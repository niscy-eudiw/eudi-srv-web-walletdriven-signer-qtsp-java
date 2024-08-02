package eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.tokens.Oid4vpAuthorizationResponseToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Oid4vpAuthorizationResponseToken authorizationResponseToken = (Oid4vpAuthorizationResponseToken) authentication;

        UriComponentsBuilder uriBuilder = UriComponentsBuilder
              .fromUriString(authorizationResponseToken.getRedirectUri())
              .queryParam(OAuth2ParameterNames.CODE,
                    authorizationResponseToken.getAuthorizationCode().getTokenValue());
        if (StringUtils.hasText(authorizationResponseToken.getState())) {
            uriBuilder.queryParam(OAuth2ParameterNames.STATE,
                  UriUtils.encode(authorizationResponseToken.getState(), StandardCharsets.UTF_8));
        }
        String redirectUri = uriBuilder.build(true).toUriString();
        this.redirectStrategy.sendRedirect(request, response, redirectUri);
    }
}
