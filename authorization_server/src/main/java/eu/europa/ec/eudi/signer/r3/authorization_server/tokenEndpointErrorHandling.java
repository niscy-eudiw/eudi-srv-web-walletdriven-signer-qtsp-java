package eu.europa.ec.eudi.signer.r3.authorization_server;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;

import java.io.IOException;

public class tokenEndpointErrorHandling implements AuthenticationFailureHandler {

    private HttpMessageConverter<OAuth2Error> errorResponseConverter = new OAuth2ErrorHttpMessageConverter();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);

        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
            System.out.println(((OAuth2AuthenticationException) exception).getError());
            this.errorResponseConverter.write(error, null, httpResponse);
        }
        else {
            System.out.println(AuthenticationException.class.getSimpleName() + " must be of type "
                      + OAuth2AuthenticationException.class.getName() + " but was "
                      + exception.getClass().getName());
            }
        }
}
