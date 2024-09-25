package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenId4VPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierCreatedVariable;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
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
    private final Logger logger = LogManager.getLogger(OID4VPAuthenticationFilter.class);
    private final SessionUrlRelationList sessionUrlRelationList;

    public OID4VPAuthenticationFilter(AuthenticationManager authenticationManager, VerifierClient verifierClient, OpenId4VPService openId4VPService, SessionUrlRelationList sessionUrlRelationList){
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.verifierClient = verifierClient;
        this.oid4vpService = openId4VPService;
        this.sessionUrlRelationList = sessionUrlRelationList;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        logger.info("OID4VP Authentication Endpoint");

        try {
            String code = request.getParameter("response_code");
            logger.info("Response_Code: {}", code);

            String sessionId = request.getParameter("session_id");
            logger.info("SessionID: {}", sessionId);

            VerifierCreatedVariable variables = this.verifierClient.getVerifierVariables(sessionId);
            String messageFromVerifier = this.verifierClient.getVPTokenFromVerifier(sessionId, code, variables);
            if (messageFromVerifier == null) throw new Exception("Error when trying to obtain the vp_token from Verifier.");
            logger.info("Recover message from the OID4VP Verifier.");
            System.out.println(messageFromVerifier);

            String urlToReturnTo = this.sessionUrlRelationList.getSessionInformation(sessionId).getUrlToReturnTo();
            String scope = getScopeFromSessionId(urlToReturnTo);
            logger.info("Scope: {}", scope);
            AuthenticationManagerToken unauthenticatedToken = oid4vpService.loadUserFromVerifierResponse(messageFromVerifier);
            unauthenticatedToken.setScope(scope);
            logger.info("Generated unauthenticated AuthenticationManagerToken: {}", unauthenticatedToken.getHash());

            Authentication authenticatedToken = this.getAuthenticationManager().authenticate(unauthenticatedToken);
            logger.info("Obtained authenticated Authentication Token.");
            return authenticatedToken;
        }
        catch (Exception e){
            logger.error(e.getMessage());
            return null;
        }
    }

    private String getScopeFromSessionId(String urlToReturnTo) throws Exception{
        URI uri = new URI(urlToReturnTo);
        String query = uri.getQuery();

        Map<String, String> queryPairs = new HashMap<>();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
            queryPairs.put(key, value);
        }

        String scope = queryPairs.get("scope");
        if(scope == null && queryPairs.get("authorization_details") != null)
            scope = "credential";

        return scope;
    }
}
