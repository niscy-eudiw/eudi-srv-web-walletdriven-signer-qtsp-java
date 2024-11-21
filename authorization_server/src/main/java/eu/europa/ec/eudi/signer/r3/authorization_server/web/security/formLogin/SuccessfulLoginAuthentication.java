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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class SuccessfulLoginAuthentication extends SimpleUrlAuthenticationSuccessHandler {
	private final Logger logger = LogManager.getLogger(SuccessfulLoginAuthentication.class);
	private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
	private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
	private final String baseUrl;

	private RequestCache requestCache = new HttpSessionRequestCache();

	public SuccessfulLoginAuthentication(String baseUrl) {
		this.baseUrl = baseUrl;

	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
		logger.info("In SuccessfulLoginAuthenticationHandler");
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (savedRequest == null) {
			response.setStatus(HttpServletResponse.SC_OK);
			response.getWriter().write("{\"message\": \"Authentication Successful\"}");
			response.getWriter().flush();
			return;
		}
		String targetUrlParameter = getTargetUrlParameter();
		if (isAlwaysUseDefaultTargetUrl() || (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
			this.requestCache.removeRequest(request, response);
			response.setStatus(HttpServletResponse.SC_OK);
			response.getWriter().write("{\"message\": \"Authentication Successful\"}");
			response.getWriter().flush();
			return;
		}
		clearAuthenticationAttributes(request);
		String targetUrl = savedRequest.getRedirectUrl();

		String updatedUriString;
		try {
			URI originalUri = URI.create(targetUrl);
			URI baseUri = URI.create(this.baseUrl);
			URI updatedUri = new URI(baseUri.getScheme(), originalUri.getUserInfo(), baseUri.getHost(),
				  baseUri.getPort(), originalUri.getPath(), originalUri.getRawQuery(), originalUri.getFragment());
			updatedUriString = updatedUri.toString();

			UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
			UsernamePasswordAuthenticationTokenExtended authenticatedToken =
				  new UsernamePasswordAuthenticationTokenExtended(token.getPrincipal(), token.getCredentials(), token.getAuthorities());

			Map<String, String> queryValues = getQueryValues(originalUri.getRawQuery());

			String scope = getScopeFromOAuth2Request(queryValues);
			authenticatedToken.setScope(scope);

			String client_id = getClientIdFromOAuth2Request(queryValues);
			if (client_id != null) authenticatedToken.setClient_id(client_id);

			String redirect_uri = getRedirectUriFromOAuth2Request(queryValues);
			if (redirect_uri != null) authenticatedToken.setRedirect_uri(redirect_uri);

			String hashDocument = getHashDocumentFromOAuth2Request(queryValues);
			if (hashDocument != null) authenticatedToken.setHashDocument(hashDocument);

			String credentialId = getCredentialIDFromOAuth2Request(queryValues);
			if (credentialId != null) authenticatedToken.setCredentialID(credentialId);

			String hashAlgorithmOID = getHashAlgorithmOIDFromOAuth2Request(queryValues);
			if (hashAlgorithmOID != null) authenticatedToken.setHashAlgorithmOID(hashAlgorithmOID);

			String numSignatures = getNumSignaturesFromOAuth2Request(queryValues);
			if (numSignatures != null) authenticatedToken.setNumSignatures(numSignatures);

			String authorizationDetails = getAuthorizationDetailsFromOAuth2Request(queryValues);
			if (authorizationDetails != null) authenticatedToken.setAuthorization_details(authorizationDetails);

			SecurityContext context = securityContextHolderStrategy.createEmptyContext();
			context.setAuthentication(authenticatedToken);
			securityContextHolderStrategy.setContext(context);
			securityContextRepository.saveContext(context, request, response);

			logger.info("Redirecting to {}", updatedUriString);

			getRedirectStrategy().sendRedirect(request, response, updatedUriString);
		}
		catch (URISyntaxException e){
			logger.error(e.getMessage());
			throw new IOException(e.getMessage());
		}
		catch (Exception e){
			logger.error(e.getMessage());
			throw new IOException(e.getMessage());
		}
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}

	private Map<String, String> getQueryValues(String query){
		Map<String, String> queryPairs = new HashMap<>();
		String[] pairs = query.split("&");
		for (String pair : pairs) {
			int idx = pair.indexOf("=");
			if(idx != -1) {
				String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
				String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
				queryPairs.put(key, value);
			}
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

	private String getAuthorizationDetailsFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("authorization_details");
	}
}
