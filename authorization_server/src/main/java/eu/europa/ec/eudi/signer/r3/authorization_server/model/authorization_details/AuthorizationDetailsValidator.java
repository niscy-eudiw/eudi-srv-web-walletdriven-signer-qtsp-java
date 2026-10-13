/*
 Copyright 2026 European Commission

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
package eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details;

import java.util.List;

import org.slf4j.Logger;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.dto.AuthorizationDetails;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.AuthorizationDetailsException;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.util.OAuth2ValidationUtils;

public final class AuthorizationDetailsValidator {
    public static void validate(String authorizationDetails, Logger logger, OAuth2AuthorizationCodeRequestAuthenticationToken token) throws OAuth2AuthorizationCodeRequestAuthenticationException {
        try {
			List<AuthorizationDetails> entries = AuthorizationDetailsParser.parse(authorizationDetails);
            for (AuthorizationDetails entry : entries) {
                entry.validate();
            }
        } catch (AuthorizationDetailsException e) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, e.getMessage()),
                    token);
        }

    }

    public static boolean matches(String first, String second) {
        if (first == null || second == null) {
            return first == null && second == null;
        }
        try {
            validateMatches(first, second);
            return true;
        } catch (AuthorizationDetailsException e) {
            return false;
        }
    }

    public static void validateMatches(String authorizedAuthorizationDetails, String requestedAuthorizationDetails) throws AuthorizationDetailsException {
        if (authorizedAuthorizationDetails == null || requestedAuthorizationDetails == null) {
            throw new AuthorizationDetailsException("The Authorization Details are either missing from the tokenRequest or from the authorizationRequest.");
        }

        if (!AuthorizationDetailsParser.toJsonArray(authorizedAuthorizationDetails).similar(AuthorizationDetailsParser.toJsonArray(requestedAuthorizationDetails))) {
            throw new AuthorizationDetailsException("The Authorization Details from the tokenRequest doesn't match the Authorization Details from the authorizationRequest.");
        }
    }
}
