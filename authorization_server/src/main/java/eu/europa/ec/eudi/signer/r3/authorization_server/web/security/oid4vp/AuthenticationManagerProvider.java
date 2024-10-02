package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationManagerProvider implements AuthenticationProvider {

    private final CustomUserDetailsService userDetailsService;
    private final Logger logger = LogManager.getLogger(AuthenticationManagerProvider.class);

    public AuthenticationManagerProvider(@Autowired CustomUserDetailsService userDetailsService){
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
        logger.info("Recover the username from the AuthenticationManagerToken: {}", username);

        // loads the user found with the given username (if it exists)
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null) throw new UsernameNotFoundException("User Not Found");
        logger.info("Found an User with the username {}", username);

        // returns an authenticated token
        AuthenticationManagerToken result = AuthenticationManagerToken.authenticated(userDetails, userDetails.getAuthorities());
        result.setScope(auth.getScope());
        result.setDetails(authentication.getDetails());
        logger.info("Generated authenticated AuthenticationManagerToken: {}", result.getHash());

        return result;
    }
}
