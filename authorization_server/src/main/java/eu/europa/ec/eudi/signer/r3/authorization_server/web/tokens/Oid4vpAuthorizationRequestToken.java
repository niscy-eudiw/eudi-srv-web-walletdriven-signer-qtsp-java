package eu.europa.ec.eudi.signer.r3.authorization_server.web.tokens;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class Oid4vpAuthorizationRequestToken extends AbstractAuthenticationToken {

    private String deeplink;

    public Oid4vpAuthorizationRequestToken(String deeplink){
        super(null);
        this.deeplink = deeplink;
        this.setAuthenticated(true);
    }

    public Oid4vpAuthorizationRequestToken(Collection<? extends GrantedAuthority> authorities, String deeplink) {
        super(authorities);
        this.deeplink = deeplink;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    public String getDeeplink() {
        return deeplink;
    }

    public void setDeeplink(String deeplink) {
        this.deeplink = deeplink;
    }
}
