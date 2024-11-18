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

public class AuthenticationManagerProvider implements AuthenticationProvider {

    private final CustomUserDetailsService userDetailsService;
    private final Logger logger = LogManager.getLogger(AuthenticationManagerProvider.class);

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
        logger.info("Recover the username from the AuthenticationManagerToken: {}", username);

        // loads the user found with the given username (if it exists)
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null){
            throw new AuthenticationServiceException("User authentication failed.");
        }
        logger.info("Found an User with the username {}", username);

        // returns an authenticated token
        AuthenticationManagerToken result = AuthenticationManagerToken.authenticated(userDetails, userDetails.getAuthorities());
        result.setScope(auth.getScope());
        result.setDetails(authentication.getDetails());
        logger.info("Generated authenticated AuthenticationManagerToken: {}", result.getHash());

        return result;
    }
}