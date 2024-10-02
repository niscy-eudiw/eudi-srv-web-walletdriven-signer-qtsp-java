package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.OAuth2IssuerConfig;
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
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.Assert;

/**
 * Used by the Exception Translation Filter to commence a login authentication with OID4VP via the OID4VPAuthenticationTokenFilter.
 * Generates a link to the Wallet, where the user will authorize sharing the PID required data.
 */
public class OID4VPAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {
    private String realmName;

    private final VerifierClient verifierClient;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final Logger logger = LogManager.getLogger(OID4VPAuthenticationEntryPoint.class);
    private final OAuth2IssuerConfig issuerConfig;
    private final SessionUrlRelationList sessionUrlRelationList;

    public OID4VPAuthenticationEntryPoint(@Autowired VerifierClient service, @Autowired OAuth2IssuerConfig issuerConfig, @Autowired SessionUrlRelationList sessionUrlRelationList){
        this.verifierClient = service;
        this.issuerConfig = issuerConfig;
        this.sessionUrlRelationList = sessionUrlRelationList;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        try{
            String serviceUrl = this.issuerConfig.getUrl();
            logger.info("Authorization Server Url: {}", serviceUrl);

            String returnTo = serviceUrl+"/oauth2/authorize?"+request.getQueryString();
            logger.info("Link to return to after authentication: {}", returnTo);

            Cookie[] cookies = request.getCookies();
            String cookieSession = null;
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("JSESSIONID".equals(cookie.getName())) {
                        cookieSession = cookie.getValue();
                        break;
                    }
                }
            }
            if(cookieSession == null) {
                String cookieHeader = response.getHeader("Set-Cookie");
                if (cookieHeader != null) {
                    String[] cookiesArray = cookieHeader.split(";");
                    for (String c : cookiesArray) {
                        if (c.trim().startsWith("JSESSIONID=")) {
                            cookieSession = c.trim().substring("JSESSIONID=".length());
                            break;
                        }
                    }
                }
            }
            logger.info("Current Cookie Session: {}", cookieSession);

            AuthorizationRequestVariables variables = this.verifierClient.initPresentationTransaction(cookieSession, serviceUrl);
            this.sessionUrlRelationList.addSessionUrlRelation(cookieSession, returnTo);
            this.redirectStrategy.sendRedirect(request, response, variables.getRedirectLink());
        }
        catch (Exception e){
            logger.error(e.getMessage());
            throw new IOException(e.getMessage());
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.hasText(this.realmName, "realmName must be specified");
    }
}
