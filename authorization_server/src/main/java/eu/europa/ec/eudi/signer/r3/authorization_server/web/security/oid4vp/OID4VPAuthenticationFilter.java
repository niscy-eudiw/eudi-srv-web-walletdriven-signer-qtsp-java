/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token.CommonTokenSetting;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
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
    private final CommonTokenSetting commonTokenSetting = new CommonTokenSetting();
    private final Logger logger = LogManager.getLogger(OID4VPAuthenticationFilter.class);

    public OID4VPAuthenticationFilter(AuthenticationManager authenticationManager, VerifierClient verifierClient,
                                      OpenIdForVPService openId4VPService, SessionUrlRelationList sessionUrlRelationList){
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.verifierClient = verifierClient;
        this.openIdForVPService = openId4VPService;
        this.sessionUrlRelationList = sessionUrlRelationList;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        logger.info("Starting authentication from OID4VP Verifier...");
        logger.trace("Request received: {}", request.getRequestURL().toString());

        String code = request.getParameter("response_code");
        logger.info("response_code from Request: {}", code);
        String sessionId = request.getParameter("session_id");
        logger.info("session_id from Request: {}", sessionId);

        String sanitizedSessionId = WebUtils.getSanitizedCookieString(sessionId);

        try {
            // Returns OID4VPException with a correctly formatted messages from the Error.description
            String messageFromVerifier = this.verifierClient.getVPTokenFromVerifier(sanitizedSessionId, code);
            logger.info("Retrieved the VP Token from the Verifier.");
            logger.debug("VP Token received: {}", messageFromVerifier);

            // Returns OID4VPException with a correctly formatted messages from the Error.description
            OID4VPAuthenticationToken unauthenticatedToken = openIdForVPService.loadUserFromVerifierResponse(messageFromVerifier);
            logger.info("Generated unauthenticated AuthenticationManagerToken: {}", unauthenticatedToken.getHash());

            // Returns AuthenticationServiceException with a correctly formatted messages
            OID4VPAuthenticationToken authenticatedToken = (OID4VPAuthenticationToken) this.getAuthenticationManager().authenticate(unauthenticatedToken);
            logger.info("Generated authenticate AuthenticationManagerToken: {}", ((UserPrincipal)authenticatedToken.getPrincipal()).getUsername());

            String urlToReturnTo = this.sessionUrlRelationList.getSessionInformation(sanitizedSessionId).getUrlToReturnTo();
            URI url = new URI(urlToReturnTo);
            this.commonTokenSetting.setCommonParameters(authenticatedToken, url);
            logger.info("Added additional parameters to the Authentication Token.");

            logger.debug(authenticatedToken.toString());
            logger.info("Obtained authenticated Authentication Token for User: {}", ((UserPrincipal)authenticatedToken.getPrincipal()).getUsername());
            return authenticatedToken;
        }
        catch (OID4VPException e){
            logger.error(e.getFormattedMessage());
            if(e.getError().equals(OID4VPEnumError.VPTokenMissingValues))
                throw new AuthenticationServiceException(e.getMessage());
            else throw new AuthenticationServiceException(e.getError().getFormattedMessage());
        }
        catch (URISyntaxException e){
            logger.error("Unable to add additional information to Authentication Token, " +
                  "because the URL to return to after OID4VP Authentication is incorrectly formatted.");
            logger.error(e.getMessage());
            throw new AuthenticationServiceException(OID4VPEnumError.UnexpectedError.getFormattedMessage());
        }
    }
}
