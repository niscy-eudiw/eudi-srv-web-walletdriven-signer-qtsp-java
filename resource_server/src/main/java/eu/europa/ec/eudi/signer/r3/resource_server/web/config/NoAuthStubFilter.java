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

package eu.europa.ec.eudi.signer.r3.resource_server.web.config;

import eu.europa.ec.eudi.signer.r3.common_tools.utils.JWTCustomClaimNames;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Development-only filter active under the "noauth" Spring profile.
 * Injects a fake JWT principal with stub claim values so controller
 * logic that reads claims (sub, givenName, surname, etc.) works without
 * a real token. The stub sub ("noauth-dev-user") must match an existing
 * user row in the database if you want credentials/list or signHash to work.
 */
public class NoAuthStubFilter extends OncePerRequestFilter {

    // Change this to match a real user hash in your local DB
    public static final String STUB_SUB = "noauth-dev-user";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            Map<String, Object> headers = Map.of("alg", "none");
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", STUB_SUB);
            claims.put(JWTCustomClaimNames.GIVEN_NAME, "Dev");
            claims.put(JWTCustomClaimNames.SURNAME, "User");
            claims.put(JWTCustomClaimNames.ISSUING_COUNTRY, "UT");
            // Stub signing claims — populate with real values if testing signHash
            claims.put(JWTCustomClaimNames.CREDENTIAL_ID, "stub-credential-id");
            claims.put(JWTCustomClaimNames.NUM_SIGNATURES, "1");
            claims.put(JWTCustomClaimNames.HASH_ALGORITHM_OID, "2.16.840.1.101.3.4.2.1");
            claims.put(JWTCustomClaimNames.HASHES, "");

            Jwt stubJwt = new Jwt("stub-token", Instant.now(), Instant.now().plusSeconds(3600),
                    headers, claims);

            JwtAuthenticationToken auth = new JwtAuthenticationToken(stubJwt,
                    List.of(new SimpleGrantedAuthority("SCOPE_service"),
                            new SimpleGrantedAuthority("SCOPE_credential")));
            auth.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
    }
}
