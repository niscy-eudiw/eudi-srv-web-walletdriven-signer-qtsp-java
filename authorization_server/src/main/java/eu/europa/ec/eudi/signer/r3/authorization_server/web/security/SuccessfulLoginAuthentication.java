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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

import java.io.EOFException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class SuccessfulLoginAuthentication extends SimpleUrlAuthenticationSuccessHandler {
	private final Logger logger = LogManager.getLogger(SuccessfulLoginAuthentication.class);
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
				  baseUri.getPort(), originalUri.getPath(),
				  originalUri.getQuery(), originalUri.getFragment());

			updatedUriString = updatedUri.toString();
		}
		catch (URISyntaxException e){
			logger.error(e.getMessage());
			throw new IOException(e.getMessage());
		}
		logger.info("Redirecting to {}", updatedUriString);

		getRedirectStrategy().sendRedirect(request, response, updatedUriString);
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}
}
