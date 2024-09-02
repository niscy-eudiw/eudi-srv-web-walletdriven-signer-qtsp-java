package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.OpenId4VPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.VerifierClient;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Processes an authentication via OId4VP.
 */
public class OID4VPAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/oid4vp/callback", "GET");
    private final VerifierClient verifierClient;
    private final OpenId4VPService oid4vpService;

    public OID4VPAuthenticationFilter(AuthenticationManager authenticationManager, VerifierClient verifierClient, OpenId4VPService openId4VPService){
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.verifierClient = verifierClient;
        this.oid4vpService = openId4VPService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String code = request.getParameter("response_code");
        String sessionCookie = request.getHeader("Cookie");
        System.out.println("response_code: "+code);
        System.out.println("sessionCookie: "+sessionCookie);

        try {
            String messageFromVerifier = this.verifierClient.getVPTokenFromVerifier(sessionCookie, code);
            if (messageFromVerifier == null) throw new Exception("Error when trying to obtain the vp_token from Verifier.");

            AuthenticationManagerToken unauthenticatedToken = oid4vpService.loadUserFromVerifierResponse(messageFromVerifier);
            return this.getAuthenticationManager().authenticate(unauthenticatedToken);
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
