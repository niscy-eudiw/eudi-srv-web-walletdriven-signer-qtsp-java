package eu.europa.ec.eudi.signer.r3.resource_server.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class WebSecurity {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
              .securityMatcher("/**")
              .authorizeHttpRequests(authorize ->
                    authorize
                          .requestMatchers("/csc/v2/info").permitAll()
                          .requestMatchers("/csc/v2/signatures/signHash").hasAuthority("SCOPE_credential")
                          .requestMatchers("/**").hasAuthority("SCOPE_service")
              )
              .oauth2ResourceServer(oauth2ResourceServer ->
                    oauth2ResourceServer.jwt(Customizer.withDefaults())
              );
        return http.build();
    }

}
