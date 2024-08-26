package eu.europa.ec.eudi.signer.r3.authorization_server.web;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.OpenId4VPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.VerifierClient;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


/**
 * Processes an authentication via OId4VP.
 */
public class OID4VPAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/oid4vp/callback", "GET");
    @Autowired
    private VerifierClient verifierClient;
    @Autowired
    private OpenId4VPService oid4vpService;

    public OID4VPAuthenticationFilter(AuthenticationManager authenticationManager){
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String code = request.getParameter("response_code");
        String session_id = request.getParameter("session_id");
        String authorize_request = URLDecoder.decode(session_id, StandardCharsets.UTF_8);
        System.out.println("response_code: "+code);
        System.out.println("session_id: "+session_id);
        System.out.println("Authorization URL: "+authorize_request);

        String user = "some_user";
        try {
            String messageFromVerifier = verifierClient.getVPTokenFromVerifier(user, VerifierClient.Authentication, code);
            if (messageFromVerifier == null) throw new Exception("Error when trying to obtain the vp_token from Verifier.");

            AuthenticationManagerToken unauthenticatedToken = oid4vpService.loadUserFromVerifierResponse(messageFromVerifier);
            Authentication authenticatedToken = this.getAuthenticationManager().authenticate(unauthenticatedToken);
            return authenticatedToken;
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }
}
