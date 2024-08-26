package eu.europa.ec.eudi.signer.r3.authorization_server.web.config;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize ->
				authorize
					.requestMatchers("/oid4vp/callback").permitAll()
					.anyRequest().authenticated()
			)
			.sessionManagement(session ->
				session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
		return http.build();
	}

	@Bean
	public OID4VPAuthenticationFilter authenticationFilter(
			AuthenticationManager authenticationManager,
			OID4VPAuthenticationSuccessHandler authenticationSuccessHandler){
		OID4VPAuthenticationFilter filter = new OID4VPAuthenticationFilter(authenticationManager);
		filter.setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
		return filter;
	}

	@Bean
	public OID4VPAuthenticationTokenFilter authenticationTokenFilter(){
		return new OID4VPAuthenticationTokenFilter();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationManagerProvider authenticationManagerProvider) throws Exception {
        return new ProviderManager(authenticationManagerProvider);
	}

	@Bean
	public OID4VPAuthenticationSuccessHandler myAuthenticationSuccessHandler(){
		return new OID4VPAuthenticationSuccessHandler();
	}

	@Bean
	public CustomUserDetailsService userDetailsService(UserRepository userRepository){
		return new CustomUserDetailsService(userRepository);
	}

	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}
}
