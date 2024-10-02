package eu.europa.ec.eudi.signer.r3.common_tools.utils;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class UserPrincipal implements OAuth2User, UserDetails, Serializable {
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

    public static UserPrincipal create(String id, String hash, String role, String givenName, String surname) {
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(role));
        return new UserPrincipal(id, hash, givenName, surname, authorities);
    }

    public String getId() {
        return this.id;
    }

    public String getUsername() {
        return this.hash;
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }

    @Override
    public String getName() {
        return this.getUsername();
    }

    public String getGivenName() {
        return this.givenName;
    }

    public String getSurname() {
        return this.surname;
    }

    public String getFullName(){
        return this.fullName;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String toString() {
        return "UserPrincipal{" +
              "id='" + id + '\'' +
              ", givenName='" + givenName + '\'' +
              ", surname='" + surname + '\'' +
              ", fullName='" + fullName + '\'' +
              ", hash='" + hash + '\'' +
              ", authorities=" + authorities +
              ", attributes=" + attributes +
              '}';
    }
}