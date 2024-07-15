package eu.europa.ec.eudi.signer.r3.authorization_server.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.util.Assert;

import java.util.*;

public class AuthorizationCodeRequestAuthenticationToken extends OAuth2AuthorizationCodeRequestAuthenticationToken {

    public AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId,
                                                       Authentication principal, @Nullable String redirectUri,
                                                       @Nullable String state, @Nullable Set<String> scopes,
                                                       @Nullable Map<String, Object> additionalParameters) {
        super(authorizationUri, clientId, principal, redirectUri, state, scopes, additionalParameters);
    }

    public AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId,
                                                       Authentication principal, @Nullable String redirectUri,
                                                       @Nullable String state, @Nullable Set<String> scopes,
                                                       OAuth2AuthorizationCode authorizationCode) {
       super(authorizationUri, clientId, principal, authorizationCode, redirectUri, state, scopes);
    }
}
