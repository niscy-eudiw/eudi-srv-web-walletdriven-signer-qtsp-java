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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class WebSecurity {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
              .csrf(AbstractHttpConfigurer::disable)
              .authorizeHttpRequests(authorize ->
                    authorize
                          .requestMatchers("/csc/v2/info").permitAll()
                          .requestMatchers("/csc/v2/signatures/signHash").hasAuthority("SCOPE_credential")
                          .requestMatchers("/csc/v2/credentials/info").hasAnyAuthority("SCOPE_credential", "SCOPE_service")
                          .requestMatchers("/csc/v2/credentials/list").hasAuthority("SCOPE_service")
                          .anyRequest().denyAll()
              )
              .oauth2ResourceServer(oauth2ResourceServer ->
                    oauth2ResourceServer.jwt(Customizer.withDefaults())
              );
        return http.build();
    }

}
