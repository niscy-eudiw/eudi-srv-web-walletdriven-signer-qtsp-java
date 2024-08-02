package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class UserPrincipal implements OAuth2User {
    private final String id;
    private final String givenName;
    private final String surname;
    private final String fullName;
    private final String hash;
    private final Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    public UserPrincipal(String id, String hash, String givenName, String surname, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.hash = hash;
        this.givenName = givenName;
        this.surname = surname;
        this.fullName = givenName + " " + surname;
        this.authorities = authorities;
    }

    public static UserPrincipal create(User user, String givenName, String surname) {
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getRole()));
        return new UserPrincipal( user.getId(), user.getHash(), givenName, surname, authorities);
    }

    public String getId() {
        return this.id;
    }

    public String getUsername() {
        return this.hash;
    }

    @Override
    public String getName() {
        return this.fullName;
    }

    public String getGivenName() {
        return this.givenName;
    }

    public String getSurname() {
        return this.surname;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
}