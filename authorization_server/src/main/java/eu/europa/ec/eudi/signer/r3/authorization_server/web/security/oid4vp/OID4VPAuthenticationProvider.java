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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class OID4VPAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService userDetailsService;

    private final Logger logger = LogManager.getLogger(OID4VPAuthenticationProvider.class);

    public OID4VPAuthenticationProvider(CustomUserDetailsService userDetailsService){
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(OID4VPAuthenticationToken.class);
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        // gets the username from the unauthenticated
        OID4VPAuthenticationToken auth = (OID4VPAuthenticationToken) authentication;
        String username = (auth.getPrincipal() == null) ? "NONE_PROVIDED" : auth.getUsername();
        logger.info("Recover the username from the AuthenticationManagerToken: {}", username);

        // loads the user found with the given username (if it exists)
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null){
            throw new AuthenticationServiceException("User authentication failed.");
        }
        logger.info("Found an User with the username {}", username);

        // returns an authenticated token
        OID4VPAuthenticationToken result = OID4VPAuthenticationToken.authenticated(userDetails, userDetails.getAuthorities());
        result.setDetails(authentication.getDetails());
        logger.info("Generated authenticated AuthenticationManagerToken: {}", result.getHash());

        return result;
    }
}
