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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.handler;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

public class OID4VPAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(OID4VPAuthenticationFailureHandler.class);

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        OID4VPEnumError error = null;
        if(exception.getMessage().equals("certificate_issuerauth_invalid")){
            error = OID4VPEnumError.CERTIFICATE_ISSUER_AUTH_INVALID;
        }
        else if(exception.getMessage().equals("status_vptoken_invalid")){
            error = OID4VPEnumError.STATUS_VP_TOKEN_INVALID;
        }
        else if(exception.getMessage().equals("presentation_submission_missing_data")){
            error = OID4VPEnumError.PRESENTATION_SUBMISSION_MISSING_DATA;
        }

        logger.error("Error received after attempting authentication with OId4VP. Message: {}", error != null ? error.getFormattedMessage() : exception.getMessage());

        HttpSession session = request.getSession();
        if(error != null) session.setAttribute("errorMessage", error.getFormattedMessageWithoutAdditionalInformation());
        else session.setAttribute("errorMessage", exception.getMessage());

        if(error != null) session.setAttribute("errorMessageAdditionalInfo", error.getAdditionalInformation());

        response.sendRedirect("/error-page");
        logger.info("Redirecting to error-page.");
    }
}
