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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@EnableWebSecurity
public class WebSecurity {

      /**
       * Production security config (active by default).
       * Enforces JWT validation and scope-based access control on all CSC endpoints.
       */
      @Configuration(proxyBeanMethods = false)
      @Profile("!noauth")
      public static class SecureConfig {

            @Bean
            SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                  http
                        .csrf(AbstractHttpConfigurer::disable)
                        .authorizeHttpRequests(authorize -> authorize
                              .requestMatchers("/swagger-ui/**").permitAll()
                              .requestMatchers("/v3/api-docs/**").permitAll()
                              .requestMatchers("/csc/v2/info").permitAll()
                              .requestMatchers("/csc/v2/signatures/signHash").hasAuthority("SCOPE_credential")
                              .requestMatchers("/csc/v2/credentials/info").hasAnyAuthority("SCOPE_credential", "SCOPE_service", "SCOPE_credential_creation", "SCOPE_credential_deletion")
                              .requestMatchers("/csc/v2/credentials/list").hasAnyAuthority("SCOPE_service", "SCOPE_credential", "SCOPE_credential_creation", "SCOPE_credential_deletion")
                              .requestMatchers("/csc/v2/credentials/create").hasAuthority("SCOPE_credential_creation")
                              .requestMatchers("/csc/v2/credentials/delete").hasAuthority("SCOPE_credential_deletion")
                              .anyRequest().denyAll())
                        .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()));
                  return http.build();
            }
      }

      /**
       * No-auth security config for local development and testing only.
       * Activated with: -Dspring.profiles.active=noauth
       *
       * Injects a stub JWT principal via NoAuthStubFilter so all controller
       * claim-reading code works without a real token. The stub sub value
       * in NoAuthStubFilter must match a real user row in your local DB.
       *
       * WARNING: disables all authentication and authorization.
       * NEVER activate this profile in production or staging environments.
       */
      @Configuration(proxyBeanMethods = false)
      @Profile("noauth")
      public static class NoAuthConfig {

            @Bean
            NoAuthStubFilter noAuthStubFilter() {
                  return new NoAuthStubFilter();
            }

            @Bean
            SecurityFilterChain securityFilterChain(HttpSecurity http, NoAuthStubFilter noAuthStubFilter)
                        throws Exception {
                  http
                              .csrf(AbstractHttpConfigurer::disable)
                              .addFilterBefore(noAuthStubFilter, AnonymousAuthenticationFilter.class)
                              .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
                  // No oauth2ResourceServer — JWT validation filter is never registered
                  return http.build();
            }
      }
}
