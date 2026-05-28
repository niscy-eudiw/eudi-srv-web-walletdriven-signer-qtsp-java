package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.util;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.credentials.CredentialsService;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin.UsernamePasswordAuthenticationTokenExtended;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2AuthorizationDetailsNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.OID4VPAuthenticationToken;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
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

import java.security.MessageDigest;
import java.util.*;

public class OAuth2ValidationUtils {
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
		if (!StringUtils.hasText(codeChallengeMethod) ||
				(!codeChallengeMethod.equals("S256") && !codeChallengeMethod.equals("plain"))) {
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
				|| (!codeChallengeMethod.equals("S256") && !codeChallengeMethod.equals("plain"))) {
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
		if (codeChallengeMethod.equals("plain") && !Objects.equals(codeVerifier, codeChallenge)) {
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

		if (!registeredClient.getRedirectUris().contains(redirectUri))
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(
					OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
							"Invalid redirect_uri parameter value."),
					token);

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
		if (StringUtils.hasText(authorizeRedirectUri) && !authorizeRedirectUri.equals(tokenRedirectUri))
			throw new OAuth2AuthenticationException(
					OAuth2ValidationUtils.getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
							"redirect_uri does not match the redirect_uri parameter of authorization request."));
	}

	/**
	 * Validates the top-level structure of an authorization_details array.
	 * Dispatches per-type validation to dedicated helper methods.
	 * Accepted types: "credential" (1.1.4), "credential_creation" (1.1.2),
	 * "credential_delete" (1.1.3).
	 */
	public static void isAuthorizationDetailsValid(Logger logger, String authorizationDetails,
			OAuth2AuthorizationCodeRequestAuthenticationToken token) throws OAuth2AuthenticationException {
		try {
			JSONArray authorizationDetailsArray = new JSONArray(authorizationDetails);
			if (authorizationDetailsArray.isEmpty()) {
				throw new OAuth2AuthorizationCodeRequestAuthenticationException(
						getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
								"Authorization Details Object is missing."),
						token);
			}

			for (int i = 0; i < authorizationDetailsArray.length(); i++) {
				JSONObject ad = authorizationDetailsArray.getJSONObject(i);
				if (!ad.has(OAuth2AuthorizationDetailsNames.TYPE))
					throw new OAuth2AuthorizationCodeRequestAuthenticationException(
							getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
									"The 'type' in the 'authorization_details' parameter is missing."),
							token);

				String type = ad.getString(OAuth2AuthorizationDetailsNames.TYPE);
				if(OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL.contains(type))
					validateCredentialAuthorizationDetails(logger, ad, token);
				else if(OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_CREATION.contains(type))
					validateCredentialCreationAuthorizationDetails(logger, ad, token);
				else if(OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_DELETE.contains(type))
					validateCredentialDeleteAuthorizationDetails(logger, ad, token);
				else throw new OAuth2AuthorizationCodeRequestAuthenticationException(
					  getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,"The 'type' in the 'authorization_details' parameter is invalid: " + type),
						  token);
			}
		} catch (JSONException e) {
			logger.error("Error {}.", e.getMessage());
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(
					getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
							"The 'authorization_details' parameter in the request is invalid."),
					token);
		}
	}

	/**
	 * Validates authorization_details for type "credential" (1.1.4).
	 * Required: credentialID or signatureQualifier, numSignatures,
	 * hashAlgorithmOID, documentDigests[].hash
	 * Optional: documentDigests[].hashType, documentDigests[].signed_props,
	 * documentDigests[].circumstantialData
	 */
	private static void validateCredentialAuthorizationDetails(Logger logger, JSONObject ad,
			OAuth2AuthorizationCodeRequestAuthenticationToken token) {
		String credentialID = ad.optString(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID, null);
		String signatureQualifier = ad.optString(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER, null);
		if (credentialID == null && signatureQualifier == null) {
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(
					getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
							"The 'credentialID' and 'signatureQualifier' in the 'authorization_details' parameter are both missing."),
					token);
		}
		if (!ad.has(OAuth2AuthorizationDetailsNames.NUM_SIGNATURES)) {
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(
					getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
							"The 'numSignatures' in the 'authorization_details' parameter is missing."),
					token);
		}
		if (!ad.has(OAuth2AuthorizationDetailsNames.HASH_ALGORITHM_OID)) {
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(
					getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
							"The 'hashAlgorithmOID' in the 'authorization_details' parameter is missing."),
					token);
		}
		if (!ad.has(OAuth2AuthorizationDetailsNames.DOCUMENT_DIGESTS)) {
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(
					getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
							"The 'documentDigests' in the 'authorization_details' parameter is missing."),
					token);
		}
		for (Object obj : ad.getJSONArray(OAuth2AuthorizationDetailsNames.DOCUMENT_DIGESTS)) {
			JSONObject documentDigest = (JSONObject) obj;
			if (!documentDigest.has(OAuth2AuthorizationDetailsNames.HASH)) {
				throw new OAuth2AuthorizationCodeRequestAuthenticationException(
						getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
								"The 'hash' in 'documentDigests' within 'authorization_details' is missing."),
						token);
			}
			// hashType, signed_props, circumstantialData are optional — no validation
			// needed
		}
	}

	/**
	 * Validates authorization_details for type "credential_creation" (1.1.2).
	 * Required: credentialCreationRequest (contains certificatePolicy
	 * conditionally, subjectData optionally)
	 * Optional: acr_values
	 */
	private static void validateCredentialCreationAuthorizationDetails(Logger logger, JSONObject ad,
			OAuth2AuthorizationCodeRequestAuthenticationToken token) {
		if (!ad.has(OAuth2AuthorizationDetailsNames.CREDENTIAL_CREATION_REQUEST)) {
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
							"The 'credentialCreationRequest' in the 'authorization_details' parameter is missing."),
					token);
		}
		// acr_values and subjectData are optional — no further required-field checks
	}

	/**
	 * Validates authorization_details for type "credential_delete" (1.1.3).
	 * Required: credentialID
	 */
	private static void validateCredentialDeleteAuthorizationDetails(Logger logger, JSONObject ad,
			OAuth2AuthorizationCodeRequestAuthenticationToken token) {
		if (!ad.has(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID)) {
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(
					getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_REQUEST,
							"The 'credentialID' in the 'authorization_details' parameter is missing for credential_delete."),
					token);
		}
	}

	public static void validateAuthorizationDetails(Logger logger, Object authorizeRequestAuthorizationDetails,
			Object tokenRequestAuthorizationDetails) throws OAuth2AuthenticationException {

		if (tokenRequestAuthorizationDetails == null) {
			throw new OAuth2AuthenticationException(getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
					"The Authorization Details are either missing from the tokenRequest or from the authorizationRequest."));
		}

		String authorizeRequestAuthorizationDetailsString = authorizeRequestAuthorizationDetails.toString();
		logger.info("Authorized Authorization Details: {}", authorizeRequestAuthorizationDetailsString);

		String tokenRequestAuthorizationDetailsString = tokenRequestAuthorizationDetails.toString();
		logger.info("Token Authorization Details: {}", tokenRequestAuthorizationDetailsString);

		JSONArray authorizeRequestAuthorizationDetailsJSONArray = new JSONArray(
				authorizeRequestAuthorizationDetailsString);
		JSONArray tokenRequestAuthorizationDetailsJSONArray = new JSONArray(tokenRequestAuthorizationDetailsString);

		if (!authorizeRequestAuthorizationDetailsJSONArray.similar(tokenRequestAuthorizationDetailsJSONArray)) {
			throw new OAuth2AuthenticationException(getOAuth2Error(logger, OAuth2ErrorCodes.INVALID_GRANT,
					"The Authorization Details from the tokenRequest doesn't match the Authorization Details from the authorizationRequest."));
		}
		logger.info("Validated authorization_details from Token Request and Authorization Details");
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
			CredentialsService credentialsService,
			Authentication principal, Map<String, Object> additionalParameters,
			String authorizeRequestAuthorizationDetailsString) {

		JSONArray authorizeRequestAuthorizationDetailsJSONArray = new JSONArray(
				authorizeRequestAuthorizationDetailsString);
		JSONArray authorizeRequestAuthorizationDetailsCopy = new JSONArray();
		for (int i = 0; i < authorizeRequestAuthorizationDetailsJSONArray.length(); i++) {
			JSONObject authorizationDetailsJSON = authorizeRequestAuthorizationDetailsJSONArray.getJSONObject(i);
			logger.info(authorizationDetailsJSON.toString());
			if (!authorizationDetailsJSON.has(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID)
					&& authorizationDetailsJSON.has(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER)) {
				String userHash = retrieveUserHash(principal);
				String credentialIdChosen = credentialsService.getCredentialIDFromSignatureQualifier(userHash,
						authorizationDetailsJSON.getString(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER));
				logger.info("CredentialId Selected: {}", credentialIdChosen);
				authorizationDetailsJSON.remove(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER);
				authorizationDetailsJSON.put(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID, credentialIdChosen);
			}
			authorizeRequestAuthorizationDetailsCopy.put(authorizationDetailsJSON);
		}
		logger.info(authorizeRequestAuthorizationDetailsCopy.toString());
		additionalParameters.put(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS,
				authorizeRequestAuthorizationDetailsCopy.toString());
	}
}
