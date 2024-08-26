package eu.europa.ec.eudi.signer.r3.authorization_server.web;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OID4VPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.AuthorizationRequestVariables;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

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
 * Used by the Exception Translation Filter to commence a login authentication with OID4VP via the
 * OID4VPAuthenticationTokenFilter.
 *
 * Generates a link to the Wallet, where the user will authorize sharing the PID required data.
 */
public class OID4VPAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

    private String realmName;

    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();
    private final OID4VPService service;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public OID4VPAuthenticationEntryPoint(@Autowired OID4VPService service){
        this.service = service;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        System.out.println(request.getParameter("authorization_details"));

        String return_to = request.getRequestURL()+"?"+request.getQueryString();
        System.out.println(return_to);

        String scope = "service";
        String service_url = "http://localhost:9000" ;
        if(scope.equals("credential")){
            service_url = "http://localhost:9000";
        }
        else if (scope.equals("service")){
            service_url = "http://localhost:9000";
        }

        AuthorizationRequestVariables variables =  this.service.authorizationRequest("some_user", service_url, return_to);
        String url = variables.getRedirectLink();
        this.redirectStrategy.sendRedirect(request, response, url);

        /**
         * Basic Authorization Entry Point
         *
         * response.setHeader("WWW-Authenticate", "Basic realm=\"" + this.realmName + "\"");
         * response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
         */
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.hasText(this.realmName, "realmName must be specified");
    }


}
