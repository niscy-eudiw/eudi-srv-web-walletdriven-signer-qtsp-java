package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.util;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.AuthorizationDetailsParser;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.AuthorizationDetailsValidator;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.dto.AuthorizationDetails;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.dto.CredentialAuthorizationDetails;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.credentials.CredentialsService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.AuthorizationDetailsException;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin.UsernamePasswordAuthenticationTokenExtended;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.OID4VPAuthenticationToken;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;

public class OAuth2ValidationUtils {

    private static final String CODE_CHALLENGE_METHOD_PLAIN = "plain";

    public static OAuth2Error getOAuth2Error(Logger logger, String errorCode, String errorDescription) {
        logger.error(errorDescription);
        return new OAuth2Error(errorCode, errorDescription, null);
    }

    public static void validatePKCE(Logger logger,
            OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken)
            throws OAuth2AuthorizationCodeRequestAuthenticationException {
        String codeChallenge = (String) authenticationToken.getAdditionalParameters()
                .get(PkceParameterNames.CODE_CHALLENGE);
        if (!StringUtils.hasText(codeChallenge)) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST, "Error validating the code_challenge"),
                    authenticationToken);
        }
        String codeChallengeMethod = (String) authenticationToken.getAdditionalParameters()
                .get(PkceParameterNames.CODE_CHALLENGE_METHOD);
        if (!StringUtils.hasText(codeChallengeMethod)
                || (!codeChallengeMethod.equals("S256") && !codeChallengeMethod.equals(CODE_CHALLENGE_METHOD_PLAIN))) {
            OAuth2Error error = getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                    "Error validating the code_challenge_method");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
        }
        logger.info("Validated code_challenge & code_challenge_method.");
    }

    public static void validatePKCE(Logger logger, Map<String, Object> authorizeRequestAdditionalParameters,
            Map<String, Object> tokenRequestAdditionalParameters)
            throws OAuth2AuthenticationException {
        String codeChallenge = (String) authorizeRequestAdditionalParameters.get(PkceParameterNames.CODE_CHALLENGE);
        if (!StringUtils.hasText(codeChallenge)) {
            throw new OAuth2AuthenticationException(
                    getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT, "Error validating the 'code_challenge'"));
        }

        String codeChallengeMethod = (String) authorizeRequestAdditionalParameters
                .get(PkceParameterNames.CODE_CHALLENGE_METHOD);
        if (!StringUtils.hasText(codeChallengeMethod)
                || (!codeChallengeMethod.equals("S256") && !codeChallengeMethod.equals(CODE_CHALLENGE_METHOD_PLAIN))) {
            throw new OAuth2AuthenticationException(
                    getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
                            "Error validating the 'code_challenge_method'"));
        }

        String codeVerifier = (String) tokenRequestAdditionalParameters.get(PkceParameterNames.CODE_VERIFIER);
        if (!StringUtils.hasText(codeVerifier)) {
            throw new OAuth2AuthenticationException(
                    getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT, "Parameter 'code_verifier' missing."));
        }

        logger.info("Code_Challenge: {}; Code_Challenge_Method: {}; Code_Verifier: {}", codeChallenge,
                codeChallengeMethod, codeVerifier);

        // Validate PKCE
        if (codeChallengeMethod.equals("S256")) {
            String codeChallengeCalculated;
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] result = sha.digest(codeVerifier.getBytes());
                codeChallengeCalculated = Base64.getUrlEncoder().withoutPadding().encodeToString(result);
                logger.info("Code_Challenge_Calculated: {}", codeChallengeCalculated);
            } catch (Exception e) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            if (!Objects.equals(codeChallengeCalculated, codeChallenge)) {
                throw new OAuth2AuthenticationException(
                        getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
                                "The code verifier doesn't validate the previous code challenge."));
            }
        }
        if (codeChallengeMethod.equals(CODE_CHALLENGE_METHOD_PLAIN) && !Objects.equals(codeVerifier, codeChallenge)) {
            throw new OAuth2AuthenticationException(
                    getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
                            "The code verifier doesn't validate the previous code challenge."));
        }
        logger.info("Validated the code verifier.");
    }

    public static String resolveRedirectUri(Logger logger, RegisteredClient registeredClient, String redirectUri,
            OAuth2AuthorizationCodeRequestAuthenticationToken token) throws OAuth2AuthenticationException {

        if (!StringUtils.hasText(redirectUri)) {
            return registeredClient.getRedirectUris().iterator().next();
        }

        if (!registeredClient.getRedirectUris().contains(redirectUri)) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                            "Invalid redirect_uri parameter value."),
                    token);
        }

        UriComponents requestedRedirect;
        try {
            requestedRedirect = UriComponentsBuilder.fromUriString(redirectUri).build();
        } catch (Exception ex) {
            logger.error(ex.getMessage());
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                            "Invalid redirect_uri parameter value."),
                    token);
        }
        if (requestedRedirect.getFragment() != null) {
            logger.error("Invalid request: redirect_uri is missing or contains a fragment for registered client {}",
                    registeredClient.getId());
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                            "Invalid redirect_uri parameter value."),
                    token);
        }
        return redirectUri;
    }

    public static void validateRedirectUri(Logger logger, String authorizeRedirectUri, String tokenRedirectUri)
            throws OAuth2AuthenticationException {
        if (StringUtils.hasText(authorizeRedirectUri) && !authorizeRedirectUri.equals(tokenRedirectUri)) {
            throw new OAuth2AuthenticationException(
                    OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
                            "redirect_uri does not match the redirect_uri parameter of authorization request."));
        }
    }

    /**
     * Validates the top-level structure of an authorization_details array.
     * Dispatches per-type validation to dedicated helper methods. Accepted
     * types: "credential" (1.1.4), "credential_creation" (1.1.2),
     * "credential_delete" (1.1.3).
     */
    public static void isAuthorizationDetailsValid(Logger logger, String authorizationDetails, OAuth2AuthorizationCodeRequestAuthenticationToken token) throws OAuth2AuthenticationException {
        AuthorizationDetailsValidator.validate(authorizationDetails, logger, token);
    }

    public static void validateAuthorizationDetails(Logger logger, Object authorizeRequestAuthorizationDetails, Object tokenRequestAuthorizationDetails) throws OAuth2AuthenticationException {
        if (tokenRequestAuthorizationDetails == null) {
            throw new OAuth2AuthenticationException(getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
                    "The Authorization Details are either missing from the tokenRequest or from the authorizationRequest."));
        }
        String authorizeRequestAuthorizationDetailsString = authorizeRequestAuthorizationDetails.toString();
        String tokenRequestAuthorizationDetailsString = tokenRequestAuthorizationDetails.toString();

        try {
            AuthorizationDetailsValidator.validateMatches(authorizeRequestAuthorizationDetailsString, tokenRequestAuthorizationDetailsString);
            logger.info("Validated authorization_details from Token Request and Authorization Details");
        } catch (AuthorizationDetailsException e) {
            throw new OAuth2AuthenticationException(getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
                    "The Authorization Details from the tokenRequest doesn't match the Authorization Details from the authorizationRequest."));
        }
    }

    private static String retrieveUserHash(Authentication principal) {
        String userHash = null;
        if (principal instanceof OID4VPAuthenticationToken auth) {
            userHash = auth.getHash();
        } else if (principal instanceof UsernamePasswordAuthenticationTokenExtended auth) {
            UserPrincipal user = (UserPrincipal) auth.getPrincipal();
            userHash = user.getUsername();
        }
        return userHash;
    }

    public static void addCredentialIdFromSignatureQualifier(Logger logger, CredentialsService credentialsService,
            Authentication principal, Map<String, Object> additionalParameters) {
        Object signatureQualifier = additionalParameters.get(OAuth2CustomParameterNames.SIGNATURE_QUALIFIER);
        Object credentialId = additionalParameters.get(OAuth2CustomParameterNames.CREDENTIAL_ID);
        if (credentialId == null && signatureQualifier != null) {
            String userHash = retrieveUserHash(principal);
            String credentialIdChosen = credentialsService.getCredentialIDFromSignatureQualifier(userHash,
                    signatureQualifier.toString());
            logger.info("CredentialId Selected: {}", credentialIdChosen);
            additionalParameters.put(OAuth2CustomParameterNames.CREDENTIAL_ID, credentialIdChosen);
        }
    }

    public static void addCredentialIdFromSignatureQualifierToAuthorizationDetails(Logger logger,
            CredentialsService credentialsService, Authentication principal, Map<String, Object> additionalParameters,
            String authorizeRequestAuthorizationDetailsString) {

        try {
            List<AuthorizationDetails> authorizationDetailsList = AuthorizationDetailsParser.parse(authorizeRequestAuthorizationDetailsString);
            List<AuthorizationDetails> authorizationDetailsListCopy = new ArrayList();
            for (AuthorizationDetails authorizationDetails : authorizationDetailsList) {
                if (!authorizationDetails.getClass().equals(CredentialAuthorizationDetails.class)) {
                    authorizationDetailsListCopy.add(authorizationDetails);
                    continue;
                }
                CredentialAuthorizationDetails credentialAuthorizationDetails = (CredentialAuthorizationDetails) authorizationDetails;
                if (credentialAuthorizationDetails.getCredentialId() == null && credentialAuthorizationDetails.getSignatureQualifier() != null) {
                    String userHash = retrieveUserHash(principal);
                    String credentialIdChosen = credentialsService.getCredentialIDFromSignatureQualifier(userHash, credentialAuthorizationDetails.getSignatureQualifier());
                    credentialAuthorizationDetails.setCredentialId(credentialIdChosen);
                    credentialAuthorizationDetails.removeSignatureQualifier();
                    authorizationDetailsListCopy.add(credentialAuthorizationDetails);
                }
            }
            additionalParameters.put(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, AuthorizationDetailsParser.serialize(authorizationDetailsListCopy));
        } catch (Exception e) {
            logger.error("Error while adding credentialId from signatureQualifier to authorizationDetails: {}", e.getMessage());
        }
    }
}
