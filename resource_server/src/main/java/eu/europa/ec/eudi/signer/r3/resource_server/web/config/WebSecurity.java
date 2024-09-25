package eu.europa.ec.eudi.signer.r3.resource_server.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class WebSecurity {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
              // .securityMatcher("/**")
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
