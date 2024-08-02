package eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.tokens.Oid4vpAuthorizationRequestToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

public class CustomAuthenticationSuccessSecondHandler implements AuthenticationSuccessHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        System.out.println("here");

        Oid4vpAuthorizationRequestToken authorizationCodeRequestAuthentication = (Oid4vpAuthorizationRequestToken) authentication;

        /*UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder
              .fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
              .replacePath(this.verificationUri);
        String verificationUri = uriComponentsBuilder.build().toUriString();

        String verificationUriComplete = uriComponentsBuilder
              .queryParam(OAuth2ParameterNames.USER_CODE, userCode.getTokenValue())
              .build().toUriString();*/

        String deepLink = authorizationCodeRequestAuthentication.getDeeplink();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        HttpMessageConverter<String> httpMessageConverter = new StringHttpMessageConverter();
        httpMessageConverter.write(deepLink, null, httpResponse);
    }
}
