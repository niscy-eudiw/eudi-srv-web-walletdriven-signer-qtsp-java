package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AuthenticationManagerToken extends AbstractAuthenticationToken {
    private final String hash;
    private final String username;
    private Object principal;
    private String scope;

    public AuthenticationManagerToken(String hash, String username){
        super(null);
        this.hash = hash;
        this.username = username;
        this.principal = hash;
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
        this.hash = user.getUsername();
        this.username = user.getUsername() + ";" + user.getGivenName() + ";" + user.getSurname();
        this.principal = user;
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

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities){}

    @Override
    public Object getCredentials() {
        return null;
    }

    public String getHash() {
        return hash;
    }

    public String getUsername() {
        return username;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
