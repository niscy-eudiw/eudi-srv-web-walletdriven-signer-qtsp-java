package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

public class OID4VPAuthenticationFailureHandler implements AuthenticationFailureHandler {

    public OID4VPAuthenticationFailureHandler() {}

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        response.sendError(HttpStatus.UNAUTHORIZED.value(), exception.getMessage());
    }
}
