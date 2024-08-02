package eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp.jwt.JwtProvider;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp.jwt.JwtToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class UserAuthenticationTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(UserAuthenticationTokenProvider.class);
    private final JwtProvider jwtProvider;

    public UserAuthenticationTokenProvider(AuthConfig authProperties) {
        jwtProvider = new JwtProvider();
        jwtProvider.setTokenSecret(authProperties.getJwtTokenSecret());
    }

    public String createToken(Authentication authentication) {
        try {
            if (authentication.getClass().equals(OpenId4VPAuthenticationToken.class)) {
                UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
                String username = userPrincipal.getUsername();
                String givenName = userPrincipal.getGivenName();
                String surname = userPrincipal.getSurname();
                final JwtToken token = jwtProvider.createToken(username + ";" + givenName + ";" + surname);
                return token.getRawToken();
            } else {
                UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
                String subject = userPrincipal.getUsername();
                final JwtToken token = jwtProvider.createToken(subject);
                return token.getRawToken();
            }
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    public JwtToken validateToken(String authToken) {
        JwtToken token = jwtProvider.validateToken(authToken);
        if (!token.isValid()) {
            log.error(token.getError());
        }
        return token;
    }

}
