/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class OID4VPAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService userDetailsService;

    private final Logger logger = LoggerFactory.getLogger(OID4VPAuthenticationProvider.class);

    public OID4VPAuthenticationProvider(CustomUserDetailsService userDetailsService){
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(OID4VPAuthenticationToken.class);
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        OID4VPAuthenticationToken auth = (OID4VPAuthenticationToken) authentication;

        // Retrieve the username from the Authentication Manager Token
        String username = (auth.getPrincipal() == null) ? "NONE_PROVIDED" : auth.getUsername();
        if(username.equals("NONE_PROVIDED")){
            logger.error("Impossible to retrieve the username from the Authentication Token.");
            throw new AuthenticationServiceException("We could not process your login request. Please try again or contact support if the issue persists.");
        }
        logger.info("Retrieved the username from the AuthenticationManagerToken: {}", username);

        // search the user with the given username (if it exists)
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null){
            logger.error("User not found.");
            throw new AuthenticationServiceException("Your account could not be found. Please check your credentials and try again.");
        }
        logger.info("Found an User with the username {}", username);

        // returns an authenticated token
        OID4VPAuthenticationToken result = OID4VPAuthenticationToken.authenticated(userDetails, userDetails.getAuthorities());
        result.setDetails(authentication.getDetails());
        logger.info("Generated authenticated AuthenticationManagerToken: {}", result.getHash());
        return result;
    }
}
