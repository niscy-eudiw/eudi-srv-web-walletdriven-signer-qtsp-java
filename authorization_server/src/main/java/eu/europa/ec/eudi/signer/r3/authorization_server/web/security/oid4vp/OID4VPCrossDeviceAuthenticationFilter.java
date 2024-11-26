package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VPTokenInvalidException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class OID4VPCrossDeviceAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/oid4vp/cross-device/callback", "GET");
	private final VerifierClient verifierClient;
	private final OpenIdForVPService openIdForVPService;
	private final SessionUrlRelationList sessionUrlRelationList;
	private final Logger logger = LogManager.getLogger(OID4VPCrossDeviceAuthenticationFilter.class);

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
			if (messageFromVerifier == null) {
				String errorMessage = "It was not possible to retrieve a VP Token from the Verifier.";
				logger.error(errorMessage);
				throw new Exception(errorMessage);
			}
			logger.info("Successfully retrieved the VP Token from the Verifier.");
			logger.trace("VP Token received: {}", messageFromVerifier);

			OID4VPAuthenticationToken unauthenticatedToken = openIdForVPService.loadUserFromVerifierResponse(messageFromVerifier);
			logger.info("Generated unauthenticated AuthenticationManagerToken: {}", unauthenticatedToken.getHash());

			OID4VPAuthenticationToken authenticatedToken = (OID4VPAuthenticationToken)this.getAuthenticationManager().authenticate(unauthenticatedToken);

			String urlToReturnTo = this.sessionUrlRelationList.getSessionInformation(sanitizedSessionId).getUrlToReturnTo();
			Map<String, String> queryValues = getQueryValues(urlToReturnTo);

			String scope = getScopeFromOAuth2Request(queryValues);
			authenticatedToken.setScope(scope);

			String client_id = getClientIdFromOAuth2Request(queryValues);
			if(client_id != null) authenticatedToken.setClient_id(client_id);

			String redirect_uri = getRedirectUriFromOAuth2Request(queryValues);
			if(redirect_uri != null) authenticatedToken.setRedirect_uri(redirect_uri);

			String hashDocument = getHashDocumentFromOAuth2Request(queryValues);
			if(hashDocument != null) authenticatedToken.setHashDocument(hashDocument);

			String credentialId = getCredentialIDFromOAuth2Request(queryValues);
			if(credentialId != null) authenticatedToken.setCredentialID(credentialId);

			String hashAlgorithmOID = getHashAlgorithmOIDFromOAuth2Request(queryValues);
			if(hashAlgorithmOID != null) authenticatedToken.setHashAlgorithmOID(hashAlgorithmOID);

			String numSignatures = getNumSignaturesFromOAuth2Request(queryValues);
			if(numSignatures != null) authenticatedToken.setNumSignatures(numSignatures);

			String authorizationDetails = getAuthorizationDetailsFromOAuth2Request(queryValues);
			if(authorizationDetails != null) authenticatedToken.setAuthorization_details(authorizationDetails);

			logger.info(authenticatedToken.toString());

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

	private Map<String, String> getQueryValues(String urlToReturnTo) throws Exception{
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

		return queryPairs;
	}

	private String getClientIdFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("client_id");
	}

	private String getRedirectUriFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("redirect_uri");
	}

	private String getScopeFromOAuth2Request(Map<String, String> queryPairs) {
		String scope = queryPairs.get("scope");
		if(scope == null && queryPairs.get("authorization_details") != null)
			scope = "credential";

		return scope;
	}

	private String getHashDocumentFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("hashes");
	}

	private String getCredentialIDFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("credentialID");
	}

	private String getHashAlgorithmOIDFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("hashAlgorithmOID");
	}

	private String getNumSignaturesFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("numSignatures");
	}

	private String getAuthorizationDetailsFromOAuth2Request(Map<String, String> queryPairs) {
		return queryPairs.get("authorization_details");
	}
}
