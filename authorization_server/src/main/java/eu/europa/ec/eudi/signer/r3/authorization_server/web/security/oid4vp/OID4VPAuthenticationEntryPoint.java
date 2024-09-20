package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.AuthorizationRequestVariables;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.Assert;

/**
 * Used by the Exception Translation Filter to commence a login authentication with OID4VP via the OID4VPAuthenticationTokenFilter.
 * Generates a link to the Wallet, where the user will authorize sharing the PID required data.
 */
public class OID4VPAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

    private String realmName;

    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();
    private final VerifierClient verifierClient;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final Logger logger = LogManager.getLogger(OID4VPAuthenticationEntryPoint.class);

    public OID4VPAuthenticationEntryPoint(@Autowired VerifierClient service){
        this.verifierClient = service;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.info("Obtain Link for OID4VP Authentication");

        try{
            String returnTo = request.getRequestURL()+"?"+request.getQueryString();
            logger.info("Link to return to after authentication: {}", returnTo);

            String scheme = request.getScheme();             // "http"
            String serverName = request.getServerName();     // "localhost"
            int serverPort = request.getServerPort();        // 9000
            String contextPath = request.getContextPath();   // ""
            String serviceUrl = scheme + "://" + serverName + ":" + serverPort + contextPath;
            logger.info("Authorization Server Url: {}", serviceUrl);

            String cookieSession = response.getHeader("Set-Cookie");
            logger.info("Current Cookie Session: {}", cookieSession);

            AuthorizationRequestVariables variables = this.verifierClient.initPresentationTransaction(cookieSession, serviceUrl, returnTo);
            this.redirectStrategy.sendRedirect(request, response, variables.getRedirectLink());
        }
        catch (Exception e){
            logger.error(e.getMessage());
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.hasText(this.realmName, "realmName must be specified");
    }
}
