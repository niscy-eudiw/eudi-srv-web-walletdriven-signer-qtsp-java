package eu.europa.ec.eudi.signer.r3.authorization_server.web;

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
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        AuthenticationManagerToken auth = (AuthenticationManagerToken) authentication;
        String hash = (auth.getPrincipal() == null) ? "NONE_PROVIDED" : auth.getHash();
        System.out.println(auth.getUsername());

        UserDetails userDetails = userDetailsService.loadUserByUsername(auth.getUsername());
        if (userDetails == null) throw new UsernameNotFoundException("User Not Found");

        AuthenticationManagerToken result = AuthenticationManagerToken.authenticated(userDetails, userDetails.getAuthorities());
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AuthenticationManagerToken.class);
    }
}
