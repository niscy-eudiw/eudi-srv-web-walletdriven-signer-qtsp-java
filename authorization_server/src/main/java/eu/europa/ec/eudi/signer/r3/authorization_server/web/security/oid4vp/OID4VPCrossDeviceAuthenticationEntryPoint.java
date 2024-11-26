package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.OAuth2IssuerConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import java.io.IOException;

public class OID4VPCrossDeviceAuthenticationEntryPoint implements AuthenticationEntryPoint {
	private final Logger logger = LogManager.getLogger(OID4VPCrossDeviceAuthenticationEntryPoint.class);
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private final OAuth2IssuerConfig issuerConfig;
	private final SessionUrlRelationList sessionUrlRelationList;

	public OID4VPCrossDeviceAuthenticationEntryPoint(@Autowired OAuth2IssuerConfig issuerConfig, @Autowired SessionUrlRelationList sessionUrlRelationList){
		this.issuerConfig = issuerConfig;
		this.sessionUrlRelationList = sessionUrlRelationList;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
		logger.info("Redirecting request to OID4VPAuthentication Entry Point.");

		String serviceUrl = this.issuerConfig.getUrl();
		logger.trace("Entry Point of the Authorization Server in url: {}", serviceUrl);

		String returnTo = serviceUrl+"/oauth2/authorize?"+request.getQueryString();
		logger.info("Saved request {} to return to after authentication.", returnTo);

		String cookieSession = getCookieSessionIdValue(request, response);
		assert cookieSession != null;
		String sanitizeCookieString = WebUtils.getSanitizedCookieString(cookieSession);
		logger.info("Saved request to JSessionId Cookie {}", sanitizeCookieString);

		this.sessionUrlRelationList.addSessionUrlRelation(sanitizeCookieString, returnTo);

		String linkToCrossDevicePage = serviceUrl+"/oid4vp/cross-device?sessionId="+sanitizeCookieString;
		this.redirectStrategy.sendRedirect(request, response, linkToCrossDevicePage);
	}

	private String getCookieSessionIdValue(HttpServletRequest request, HttpServletResponse response){
		String cookieSession = null;
		Cookie[] cookies = request.getCookies();

		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if ("JSESSIONID".equals(cookie.getName())) {
					cookieSession = cookie.getValue();
					break;
				}
			}
		}
		if(cookieSession == null) {
			String cookieHeader = response.getHeader("Set-Cookie");
			if (cookieHeader != null) {
				String[] cookiesArray = cookieHeader.split(";");
				for (String c : cookiesArray) {
					if (c.trim().startsWith("JSESSIONID=")) {
						cookieSession = c.trim().substring("JSESSIONID=".length());
						break;
					}
				}
			}
		}
		logger.info("Current Cookie Session: {}", cookieSession);

		return cookieSession;
	}
}
