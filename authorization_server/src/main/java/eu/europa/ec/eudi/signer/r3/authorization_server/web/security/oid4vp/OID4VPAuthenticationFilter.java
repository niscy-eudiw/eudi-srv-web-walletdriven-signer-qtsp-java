package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VPTokenInvalidException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
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
    private final OpenIdForVPService openIdForVPService;
    private final SessionUrlRelationList sessionUrlRelationList;
    private final Logger logger = LogManager.getLogger(OID4VPAuthenticationFilter.class);

    public OID4VPAuthenticationFilter(AuthenticationManager authenticationManager, VerifierClient verifierClient, OpenIdForVPService openId4VPService, SessionUrlRelationList sessionUrlRelationList){
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.verifierClient = verifierClient;
        this.openIdForVPService = openId4VPService;
        this.sessionUrlRelationList = sessionUrlRelationList;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
          throws AuthenticationException {
        logger.info("Starting authentication from OID4VP Verifier...");
        logger.trace("Request received: {}", request.getRequestURL().toString());

        try {
            String code = request.getParameter("response_code");
            logger.trace("Response_Code from Request: {}", code);
            String sessionId = request.getParameter("session_id");
            logger.trace("SessionID from Request: {}", sessionId);

            String messageFromVerifier = this.verifierClient.getVPTokenFromVerifier(sessionId, code);
            if (messageFromVerifier == null) {
                String errorMessage = "It was not possible to retrieve a VP Token from the Verifier.";
                logger.error(errorMessage);
                throw new Exception(errorMessage);
            }
            logger.info("Successfully retrieved the VP Token from the Verifier.");
            logger.trace("VP Token received: {}", messageFromVerifier);

            String urlToReturnTo = this.sessionUrlRelationList.getSessionInformation(sessionId).getUrlToReturnTo();
            String scope = getScopeFromOAuth2Request(urlToReturnTo);
            logger.info("Scope from the OAuth2 Request: {}", scope);

            AuthenticationManagerToken unauthenticatedToken = openIdForVPService.loadUserFromVerifierResponse(messageFromVerifier);
            unauthenticatedToken.setScope(scope);
            logger.info("Generated unauthenticated AuthenticationManagerToken: {}", unauthenticatedToken.getHash());

            Authentication authenticatedToken = this.getAuthenticationManager().authenticate(unauthenticatedToken);
            logger.info("Obtained authenticated Authentication Token: {}", ((UserPrincipal)authenticatedToken.getPrincipal()).getUsername());
            return authenticatedToken;
        }
        catch (VPTokenInvalidException e){
            logger.error(e.getMessage());
            throw new AuthenticationServiceException(e.getError().getFormattedMessage());
        }
        catch (VerifiablePresentationVerificationException e){
            logger.error(e.getError().getFormattedMessage());
            logger.error(e.getMessage());
            throw new AuthenticationServiceException(e.getError().getFormattedMessage());
        }
        catch (Exception e){
            logger.error(e.getMessage());
            throw new AuthenticationServiceException(e.getMessage());
        }
    }

    private String getScopeFromOAuth2Request(String urlToReturnTo) throws Exception{
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
