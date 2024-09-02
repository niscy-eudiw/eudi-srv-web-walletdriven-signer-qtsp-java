package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationManagerProvider implements AuthenticationProvider {

    private final CustomUserDetailsService userDetailsService;

    public AuthenticationManagerProvider(CustomUserDetailsService userDetailsService){
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AuthenticationManagerToken.class);
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        // gets the username from the unauthenticated
        AuthenticationManagerToken auth = (AuthenticationManagerToken) authentication;
        String username = (auth.getPrincipal() == null) ? "NONE_PROVIDED" : auth.getUsername();
        System.out.println(username);

        // loads the user found with the given username (if it exists)
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null) throw new UsernameNotFoundException("User Not Found");

        // returns an authenticated token
        AuthenticationManagerToken result = AuthenticationManagerToken.authenticated(userDetails, userDetails.getAuthorities());
        result.setDetails(authentication.getDetails());
        return result;
    }
}
