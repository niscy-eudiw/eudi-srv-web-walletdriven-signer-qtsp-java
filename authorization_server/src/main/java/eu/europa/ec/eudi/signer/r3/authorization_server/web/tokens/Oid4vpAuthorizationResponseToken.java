package eu.europa.ec.eudi.signer.r3.authorization_server.web.tokens;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.util.Assert;

import javax.security.auth.Subject;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class Oid4vpAuthorizationResponseToken extends AbstractAuthenticationToken {

    private Authentication principal;
    private String redirect_uri;
    private OAuth2AuthorizationCode authorization_code;
    private String state;

    public Oid4vpAuthorizationResponseToken(Authentication principal, OAuth2AuthorizationCode authorizationCode, @Nullable String redirectUri, @Nullable String state) {
        super(Collections.emptyList());
        this.principal = principal;
        this.authorization_code = authorizationCode;
        this.redirect_uri = redirectUri;
        this.state = state;
        this.setAuthenticated(true);
    }

    public Oid4vpAuthorizationResponseToken(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public boolean implies(Subject subject) {
        return super.implies(subject);
    }

    public String getRedirectUri() {
        return redirect_uri;
    }

    public void setRedirectUri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }

    public OAuth2AuthorizationCode getAuthorizationCode() {
        return authorization_code;
    }

    public void setAuthorizationCode(OAuth2AuthorizationCode authorization_code) {
        this.authorization_code = authorization_code;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }
}
