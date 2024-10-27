package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.provider;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.ManageOAuth2Authorization;
import java.security.Principal;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

public class AuthorizationRequestProvider implements AuthenticationProvider {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
    private final OAuth2AuthorizationService authorizationService;
    private final ManageOAuth2Authorization manageOAuth2Authorization;
    private final Logger logger = LogManager.getLogger(AuthorizationRequestProvider.class);

    private static class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {

        private final StringKeyGenerator authorizationCodeGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

        @Nullable
        @Override
        public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
            if (context.getTokenType() == null || !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
            return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
        }
    }

    public AuthorizationRequestProvider(RegisteredClientRepository registeredClientRepository,
                                        OAuth2AuthorizationService authorizationService,
                                        ManageOAuth2Authorization manageOAuth2Authorization) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.manageOAuth2Authorization = manageOAuth2Authorization;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2Error getOAuth2Error(String errorCode, String errorDescription){
        logger.error(errorDescription);
        return new OAuth2Error(errorCode, errorDescription, null);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken =
              (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        logger.info("Authenticating an Authorization Code Request for the clientID: {}.", authenticationToken.getClientId());

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(authenticationToken.getClientId());
        if (registeredClient == null) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                  "ClientID " + authenticationToken.getClientId() + " from the request not found.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
        }
        logger.info("ClientID from AuthenticationToken is registered.");

        AuthorizationGrantType grantType = validateAndFetchAuthorizationGrantType(registeredClient, authenticationToken);

        String redirectUri = validateAndFetchRedirectUri(registeredClient, authenticationToken);

        Set<String> requestedScopes = validateAndFetchScopes(registeredClient, authenticationToken);

        validatePKCEParameter(authenticationToken);

        String authorizationDetails = (String) authenticationToken.getAdditionalParameters().get("authorization_details");
        if(authorizationDetails != null){
            validateAuthorizationDetails(authorizationDetails, authenticationToken);
        }

        // The request is valid - ensure the resource owner is authenticated
        Authentication principal = (Authentication) authenticationToken.getPrincipal();
        if (!isPrincipalAuthenticated(principal)) {
            logger.warn("Did not authenticate authorizationCode request since principal not authenticated");
            return authenticationToken;
        }
        logger.info("Principal of type {} is authenticated.", principal.getClass().getName());

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
              .authorizationUri(authenticationToken.getAuthorizationUri())
              .clientId(registeredClient.getClientId())
              .redirectUri(redirectUri)
              .scopes(requestedScopes)
              .state(authenticationToken.getState())
              .additionalParameters(authenticationToken.getAdditionalParameters())
              .build();
        logger.info("Generated OAuth2AuthorizationRequest: {}.", authorizationRequest.toString());

        OAuth2AuthorizationCode authorizationCode = generateAuthorizationCode(registeredClient, principal,
              requestedScopes, authenticationToken);
        logger.info("Generated OAuth2AuthorizationCode: {}", authorizationCode.getTokenValue());

        this.manageOAuth2Authorization.removePreviousOAuth2AuthorizationOfUser(principal.getName(), requestedScopes);

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
              .principalName(principal.getName())
              .authorizationGrantType(grantType)
              .attribute(Principal.class.getName(), principal)
              .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
              .authorizedScopes(requestedScopes)
              .token(authorizationCode)
              .build();
        this.authorizationService.save(authorization);
        logger.info("Generated and Saved OAuth2Authorization: {}.", authorization.getId());
        logger.info("Access Token: {}.", authorization.getAccessToken());
        logger.info("Authorization Code: {}.", authorization.getToken(OAuth2AuthorizationCode.class));

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationRequest.getAuthorizationUri(),
              registeredClient.getClientId(), principal, authorizationCode, redirectUri, authorizationRequest.getState(), requestedScopes);
    }

    private AuthorizationGrantType validateAndFetchAuthorizationGrantType(RegisteredClient registeredClient,
                                                                          OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken){

        AuthorizationGrantType supportedGrantType = AuthorizationGrantType.AUTHORIZATION_CODE;
        if (!registeredClient.getAuthorizationGrantTypes().contains(supportedGrantType)) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                  "Request grant_type 'authorization_code' is not allowed for the registered client.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
        }
        logger.info("Requested grant_type {}.", supportedGrantType.getValue());
        return supportedGrantType;
    }

    private String validateAndFetchRedirectUri(RegisteredClient registeredClient,
                                               OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken){

        String redirectUri = authenticationToken.getRedirectUri();

        // if a redirect URI is not passed, the default redirect URI is used
        if(!StringUtils.hasText(redirectUri)) {
            redirectUri = registeredClient.getRedirectUris().iterator().next();
        }
        else { // if the redirect URI is passed, the redirect URI should match the pre-registered values
            if(!registeredClient.getRedirectUris().contains(redirectUri)){ // if the redirectURI is not in the pre-registered values
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid redirect_uri parameter value."), authenticationToken);
            }
            else{ // if the redirectURI is in the pre-registered values, it should have a valid format
                UriComponents requestedRedirect;
                try {
                    requestedRedirect = UriComponentsBuilder.fromUriString(redirectUri).build();
                }
                catch (Exception ex) {
                    logger.error(ex.getMessage());
                    throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid redirect_uri parameter value."), authenticationToken);
                }
                if (requestedRedirect.getFragment() != null) {
                    logger.error("Invalid request: redirect_uri is missing or contains a fragment for registered client {}", registeredClient.getId());
                    throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid redirect_uri parameter value."), authenticationToken);
                }
            }
        }
        return redirectUri;
    }

    // if the scope requested is in the scopes supported:
    private Set<String> validateAndFetchScopes(RegisteredClient registeredClient,
                                               OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken){
        Set<String> requestedScopes = authenticationToken.getScopes();
        if (!CollectionUtils.isEmpty(requestedScopes)) { // the scope set is not empty
            if(!registeredClient.getScopes().containsAll(requestedScopes)) {
                OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE, "The scope requested is not supported.");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
            }
        }
        else{ // if the scope set is empty
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "The scope parameter is missing.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
        }
        logger.info("Validated that the requested scopes are supported scopes.");
        return requestedScopes;
    }

    private void validatePKCEParameter(OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken){
        String codeChallenge = (String)authenticationToken.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
        if(!StringUtils.hasText(codeChallenge)) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,"Error validating the code_challenge & code_challenge_method");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
        }
        String codeChallengeMethod = (String)authenticationToken.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
        if(!StringUtils.hasText(codeChallengeMethod) ||
              (!codeChallengeMethod.equals("S256") && !codeChallengeMethod.equals("plain"))) {
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,"Error validating the code_challenge & code_challenge_method");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
        }
        logger.info("Validated code_challenge & code_challenge_method.");
    }

    private void validateAuthorizationDetails(String authorizationDetails,
                                              OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken){
        try{
            JSONObject authorizationDetailsJSON = new JSONObject(authorizationDetails);

            String type = authorizationDetailsJSON.getString("type");
            if(type == null){
                OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                      "The 'type' in the 'authorization_details' parameter is missing.");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
            }
            if(!type.equals("credential")){
                OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                      "The 'type' in the 'authorization_details' parameter is invalid.");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
            }

            String credentialID = authorizationDetailsJSON.getString("credentialID");
            String signatureQualifier = authorizationDetailsJSON.getString("signatureQualifier");
            if(credentialID == null && signatureQualifier == null){
                OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                      "The 'credentialID' and 'signatureQualifier' in the 'authorization_details' parameter missing.");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
            }

            String hashAlgorithmOID = authorizationDetailsJSON.getString("hashAlgorithmOID");
            if(hashAlgorithmOID == null){
                OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                      "The 'hashAlgorithmOID' in the 'authorization_details' parameter is missing.");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
            }

            JSONArray documentDigests = authorizationDetailsJSON.getJSONArray("documentDigests");
            if(documentDigests == null){
                OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                      "The 'documentDigests' in the 'authorization_details' parameter is missing.");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
            }

            for (Object jsonObject: documentDigests){
                JSONObject j = (JSONObject) jsonObject;
                String hash = j.getString("hash");
                if(hash == null){
                    OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                          "The 'hash' in the 'documentDigests' in 'authorization_details' parameter is missing.");
                    throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
                }
            }
        }
        catch (JSONException e){
            OAuth2Error error = getOAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                  "The 'authorization_details' parameter in the request is invalid.");
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authenticationToken);
        }
    }


    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) && principal.isAuthenticated();
    }

    // Generate the authorization code
    private OAuth2AuthorizationCode generateAuthorizationCode(RegisteredClient registeredClient, Authentication principal,
                                                              Set<String> requestedScopes, OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken){

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
              .registeredClient(registeredClient)
              .principal(principal)
              .authorizationServerContext(AuthorizationServerContextHolder.getContext())
              .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
              .authorizedScopes(requestedScopes)
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrant(authenticationToken);
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null)
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(getOAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the authorization code."), null);

        return authorizationCode;
    }
}
