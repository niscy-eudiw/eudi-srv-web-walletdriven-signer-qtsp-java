package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token.CommonTokenSetting;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

public class OID4VPCrossDeviceAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/oid4vp/cross-device/callback", "GET");
	private final VerifierClient verifierClient;
	private final OpenIdForVPService openIdForVPService;
	private final SessionUrlRelationList sessionUrlRelationList;
	private final CommonTokenSetting commonTokenSetting = new CommonTokenSetting();
	private final Logger logger = LoggerFactory.getLogger(OID4VPCrossDeviceAuthenticationFilter.class);

	public OID4VPCrossDeviceAuthenticationFilter(AuthenticationManager authenticationManager, VerifierClient verifierClient, OpenIdForVPService openId4VPService, SessionUrlRelationList sessionUrlRelationList){
		super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
		this.verifierClient = verifierClient;
		this.openIdForVPService = openId4VPService;
		this.sessionUrlRelationList = sessionUrlRelationList;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		logger.info("Starting authentication from OID4VP Verifier...");
		logger.trace("Request received: {}", request.getRequestURL().toString());

		try {
			String sessionId = request.getParameter("session_id");
			logger.info("SessionID from Request: {}", sessionId);

			String sanitizedSessionId = WebUtils.getSanitizedCookieString(sessionId);

			String messageFromVerifier = this.verifierClient.getVPTokenFromVerifierRecursive(sanitizedSessionId);
			logger.info("Retrieved the VP Token from the Verifier.");
			logger.trace("VP Token received: {}", messageFromVerifier);

			OID4VPAuthenticationToken unauthenticatedToken = openIdForVPService.loadUserFromVerifierResponseWithVerifierValidation(messageFromVerifier);
			logger.info("Generated unauthenticated AuthenticationManagerToken: {}", unauthenticatedToken.getHash());

			OID4VPAuthenticationToken authenticatedToken = (OID4VPAuthenticationToken)this.getAuthenticationManager().authenticate(unauthenticatedToken);
			logger.info("Generated authenticate AuthenticationManagerToken: {}", ((UserPrincipal)authenticatedToken.getPrincipal()).getUsername());

			String urlToReturnTo = this.sessionUrlRelationList.getSessionInformation(sanitizedSessionId).getUrlToReturnTo();
			URI url = new URI(urlToReturnTo);
			this.commonTokenSetting.setCommonParameters(authenticatedToken, url);
			logger.info("Added additional parameters to the Authentication Token.");

			logger.debug(authenticatedToken.toString());
			logger.info("Obtained authenticated Authentication Token: {}", ((UserPrincipal)authenticatedToken.getPrincipal()).getUsername());
			return authenticatedToken;
		}
		catch (OID4VPException e){
			logger.error(e.getFormattedMessage());
			if(e.getError().equals(OID4VPEnumError.VP_TOKEN_MISSING_VALUES))
				throw new AuthenticationServiceException(e.getMessage());
			else if(!Objects.equals(e.getError().getAdditionalInformation(), "")){ // if there are additional information, sends the code to exception handler
				throw new AuthenticationServiceException(e.getError().getCode());
			}
			else throw new AuthenticationServiceException(e.getError().getFormattedMessage());
		}
		catch (InterruptedException e){
			logger.error("Unexpected error: {}", e.getMessage());
			throw new AuthenticationServiceException(OID4VPEnumError.UNEXPECTED_ERROR.getFormattedMessage());
		}
		catch (URISyntaxException e){
			logger.error("Unable to add additional information to Authentication Token, " +
				  "because the URL to return to after OID4VP Authentication is incorrectly formatted.");
			logger.error(e.getMessage());
			throw new AuthenticationServiceException(OID4VPEnumError.UNEXPECTED_ERROR.getFormattedMessage());
		}
	}
}
