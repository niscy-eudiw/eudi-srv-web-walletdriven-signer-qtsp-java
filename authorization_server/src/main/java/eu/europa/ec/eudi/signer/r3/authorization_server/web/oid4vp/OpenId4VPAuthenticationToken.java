package eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp;

import java.util.Collection;
import java.util.Objects;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.UserPrincipal;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class OpenId4VPAuthenticationToken extends AbstractAuthenticationToken {
    private final String hash;
    private final String givenName;
    private final String surname;
    private final String fullName;
    private final Object principal;
    private final Object credentials;

    public OpenId4VPAuthenticationToken(String hash, String givenName, String surname) {
        super(null);
        this.hash = hash;
        this.givenName = givenName;
        this.surname = surname;
        this.fullName = givenName + " " + surname;
        this.principal = hash;
        this.credentials = null;
    }

    public OpenId4VPAuthenticationToken(Object userPrincipal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        UserPrincipal user = (UserPrincipal) userPrincipal;
        this.hash = user.getUsername();
        this.principal = user;
        this.credentials = null;
        this.givenName = user.getGivenName();
        this.surname = user.getSurname();
        this.fullName = user.getName();
        this.setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public String getName() {
        return this.hash;
    }

    public String getGivenName() {
        return this.givenName;
    }

    public String getSurname() {
        return this.surname;
    }

    public String getHash() {
        return this.hash;
    }

    public String getFullName() {
        return this.fullName;
    }

    public String getUsername(){
        return this.hash+";"+this.givenName+";"+this.surname;
    }
}
