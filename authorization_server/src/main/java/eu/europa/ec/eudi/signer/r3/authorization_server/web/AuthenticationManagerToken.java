package eu.europa.ec.eudi.signer.r3.authorization_server.web;

import java.util.Collection;

import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AuthenticationManagerToken extends AbstractAuthenticationToken {
    private String hash;
    private String username;
    private Object principal;
    private Object credentials;

    public AuthenticationManagerToken(String hash, String username){
        super(null);
        this.hash = hash;
        this.username = username;
        this.principal = hash;
        this.credentials = null;
        super.setAuthenticated(false);
    }

    public static AuthenticationManagerToken unauthenticated(String hash, String username){
        return new AuthenticationManagerToken(hash, username);
    }

    public static AuthenticationManagerToken unauthenticated(String hash, String givenName, String surname){
        String username = hash + ";" + givenName + ";" + surname;
        return new AuthenticationManagerToken(hash, username);
    }

    public AuthenticationManagerToken(Object userPrincipal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        UserPrincipal user = (UserPrincipal) userPrincipal;
        String username = hash + ";" + user.getGivenName() + ";" + user.getSurname();
        this.hash = user.getUsername();
        this.username = username;
        this.principal = user;
        this.credentials = user.getPassword();
        super.setAuthenticated(true);
    }

    public static AuthenticationManagerToken authenticated(Object userPrincipal, Collection<? extends GrantedAuthority> authorities){
        return new AuthenticationManagerToken(userPrincipal, authorities);
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public String getName(){
        if(principal.getClass().equals(UserPrincipal.class)){
            UserPrincipal user = (UserPrincipal) principal;
            return user.getName();
        }
        else return this.principal.toString();
    }

    public void setPrincipal(Object user){
        this.principal = user;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities){

    }

    @Override
    public Object getCredentials() {
        return null;
    }

    public void setCredentials(Object credentials){
        this.credentials = credentials;
    }

    public String getHash() {
        return hash;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
