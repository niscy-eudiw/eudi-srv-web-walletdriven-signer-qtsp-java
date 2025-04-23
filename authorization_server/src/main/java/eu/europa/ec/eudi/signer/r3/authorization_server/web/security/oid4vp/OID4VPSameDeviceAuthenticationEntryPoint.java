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

import eu.europa.ec.eudi.signer.r3.authorization_server.config.OAuth2IssuerConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

/**
 * Used by the Exception Translation Filter to commence a login authentication with OID4VP via the OID4VPAuthenticationTokenFilter.
 * Generates a link to the Wallet, where the user will authorize sharing the PID required data.
 */
public class OID4VPSameDeviceAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final Logger logger = LogManager.getLogger(OID4VPSameDeviceAuthenticationEntryPoint.class);

    private final VerifierClient verifierClient;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final OAuth2IssuerConfig issuerConfig;
    private final SessionUrlRelationList sessionUrlRelationList;

    public OID4VPSameDeviceAuthenticationEntryPoint(@Autowired VerifierClient service, @Autowired OAuth2IssuerConfig issuerConfig, @Autowired SessionUrlRelationList sessionUrlRelationList){
        this.verifierClient = service;
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

        try{
            JSONArray transaction_data = getTransactionData(request);
            String redirectLink = this.verifierClient.initSameDeviceTransactionToVerifier(sanitizeCookieString, serviceUrl, transaction_data);
            this.sessionUrlRelationList.addSessionReturnToUrl(sanitizeCookieString, returnTo);
            this.redirectStrategy.sendRedirect(request, response, redirectLink);
        }
        catch (Exception e){
            logger.error(e.getMessage());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
    }

    private JSONArray getTransactionData(HttpServletRequest request){
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(request);
        logger.info("Request received: {}", authorizeRequest);

        if(authorizeRequest.getScope().equals("credential")){
            String credentialId = authorizeRequest.getCredentialID();
            String signatureQualifier = authorizeRequest.getSignatureQualifier();
            String hashes = authorizeRequest.getHashes();
            String hashAlgorithmOID = authorizeRequest.getHashAlgorithmOID();
            String description = authorizeRequest.getDescription();
            String label;
            if(description == null) label = "Document to Sign";
            else label = description;

            String[] hashArray = hashes.split(",");
            JSONArray documentDigests = new JSONArray();
            for(String hash: hashArray){
                JSONObject documentDigestObj = new JSONObject();
                documentDigestObj.put("hash", hash);
                documentDigestObj.put("label", label);
                documentDigests.put(documentDigestObj);
            }
            return verifierClient.getTransactionData(credentialId, hashAlgorithmOID, documentDigests);
        }
        else if(authorizeRequest.getAuthorization_details() != null){
            String authDetailsAuthorization = URLDecoder.decode(authorizeRequest.getAuthorization_details(), StandardCharsets.UTF_8);
            JSONArray authorizationDetailsArray = new JSONArray(authDetailsAuthorization);
            JSONObject authorizationDetailsJSON = authorizationDetailsArray.getJSONObject(0);
            String credentialID = authorizationDetailsJSON.getString("credentialID");
            String signatureQualifier = authorizationDetailsJSON.getString("signatureQualifier");
            String hashAlgorithmOID = authorizationDetailsJSON.getString("hashAlgorithmOID");
            JSONArray documentDigests = authorizationDetailsJSON.getJSONArray("documentDigests");
            JSONArray locations = authorizationDetailsJSON.getJSONArray("locations");
            return verifierClient.getTransactionData(credentialID, hashAlgorithmOID, documentDigests);
        }

        return null;
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
