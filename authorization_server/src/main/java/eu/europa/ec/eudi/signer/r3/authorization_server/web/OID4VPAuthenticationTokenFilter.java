package eu.europa.ec.eudi.signer.r3.authorization_server.web;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.OpenId4VPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.VerifierClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;


public class OID4VPAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private VerifierClient verifierClient;
    @Autowired
    private OpenId4VPService oid4vpService;
    @Autowired
    private AuthenticationManager authenticationManager;
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private RememberMeServices rememberMeServices = new NullRememberMeServices();

    //private final UserAuthenticationTokenProvider tokenProvider;
    //private final UserDetailsService customUserOID4VPDetailsService;

    public OID4VPAuthenticationTokenFilter(){
        //this.tokenProvider = tokenProvider;
        // this.customUserOID4VPDetailsService = customUserOID4VPDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println(request.getQueryString());

        /*String jwt = getJwtFromRequest(request);
        if (StringUtils.hasText(jwt)) {
            JwtToken token = tokenProvider.validateToken(jwt);
            if (token.isValid()) {
                String username = token.getSubject();
                try {
                    UserDetails userDetails2 = customUserOID4VPDetailsService.loadUserByUsername(username);
                    AuthenticationManagerToken authentication2 = new AuthenticationManagerToken(userDetails2, userDetails2.getAuthorities());
                    authentication2.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication2);
                } catch (Exception ex1) {
                    logger.error("Could not set user authentication in security context", ex1);
                }
            }
        }

        filterChain.doFilter(request, response);*/

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
            Authentication authenticatedToken = this.authenticationManager.authenticate(unauthenticatedToken);

            SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authenticatedToken);
            this.securityContextHolderStrategy.setContext(context);
            if (this.logger.isDebugEnabled()) {
                this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authenticatedToken));
            }
            this.rememberMeServices.loginSuccess(request, response, authenticatedToken);
            this.securityContextRepository.saveContext(context, request, response);
            onSuccessfulAuthentication(request, response, authenticatedToken);
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException {
    }
}
