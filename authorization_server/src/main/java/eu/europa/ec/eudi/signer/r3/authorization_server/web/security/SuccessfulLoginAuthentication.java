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

		String updatedUriString = "";
		try {
			URI originalUri = URI.create(targetUrl);
			URI baseUri = URI.create(this.baseUrl);
			URI updatedUri = new URI(baseUri.getScheme(), originalUri.getUserInfo(), baseUri.getHost(),
				  baseUri.getPort(), originalUri.getPath(),
				  originalUri.getQuery(), originalUri.getFragment());

			updatedUriString = updatedUri.toString();
		}
		catch (URISyntaxException e){
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		System.out.println(updatedUriString);

		getRedirectStrategy().sendRedirect(request, response, updatedUriString);
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}
}
