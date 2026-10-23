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

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.ServiceURLConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class OID4VPCrossDeviceAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final Logger logger = LoggerFactory.getLogger(OID4VPCrossDeviceAuthenticationEntryPoint.class);
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final ServiceURLConfig issuerConfig;
    private final SessionUrlRelationList sessionUrlRelationList;
    private final OpenIdForVPService openIdForVPService;

    public OID4VPCrossDeviceAuthenticationEntryPoint(OpenIdForVPService openIdForVPService, ServiceURLConfig issuerConfig, SessionUrlRelationList sessionUrlRelationList) {
        this.openIdForVPService = openIdForVPService;
        this.issuerConfig = issuerConfig;
        this.sessionUrlRelationList = sessionUrlRelationList;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        logger.info("Redirecting request to OID4VPAuthentication Entry Point.");

        String serviceUrl = this.issuerConfig.getServiceURL();
        logger.trace("Entry Point of the Authorization Server in url: {}", serviceUrl);

        String returnTo = serviceUrl + "/oauth2/authorize?" + request.getQueryString();
        logger.info("Saved request {} to return to after authentication.", returnTo);

        String cookieSession = getCookieSessionIdValue(request, response);
        assert cookieSession != null;
        String sanitizeCookieString = WebUtils.getSanitizedCookieString(cookieSession);
        logger.info("Saved request to JSessionId Cookie {}", sanitizeCookieString);

        this.sessionUrlRelationList.addSessionReturnToUrl(sanitizeCookieString, returnTo);

        String linkToCrossDevicePage = serviceUrl + "/oid4vp/cross-device?sessionId="+sanitizeCookieString;
        this.redirectStrategy.sendRedirect(request, response, linkToCrossDevicePage);
    }

    private String getCookieSessionIdValue(HttpServletRequest request, HttpServletResponse response) {
        String cookieSession = request.getSession(true).getId();
        logger.info("Current Cookie Session: {}", cookieSession);
        return cookieSession;
    }
}
