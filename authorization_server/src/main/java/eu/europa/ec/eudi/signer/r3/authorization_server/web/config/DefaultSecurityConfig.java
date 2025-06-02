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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.config;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.ServiceURLConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.controller.OID4VPController;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin.SuccessfulLoginAuthentication;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.*;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.handler.OID4VPAuthenticationFailureHandler;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.handler.OID4VPAuthenticationSuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import java.util.ArrayList;
import java.util.List;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig implements WebMvcConfigurer {

	private final Logger logger = LoggerFactory.getLogger(DefaultSecurityConfig.class);


	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, ServiceURLConfig issuerConfig,
														  OID4VPSameDeviceAuthenticationFilter sameDeviceAuthenticationFilter,
														  OID4VPCrossDeviceAuthenticationFilter crossDeviceAuthenticationFilter,
														  CorsConfigurationSource corsConfigurationSource) throws Exception {
		http.cors(c->c.configurationSource(corsConfigurationSource))
			  .authorizeHttpRequests(authorize ->
					authorize
						  .requestMatchers("/swagger-ui/**").permitAll()
						  .requestMatchers("/v3/api-docs/**").permitAll()
						  .requestMatchers("/oid4vp/*").permitAll()
						  .requestMatchers("/login").permitAll()
						  .requestMatchers("/error").permitAll()
						  .requestMatchers("/error-page").permitAll()
						  .requestMatchers("/static/**").permitAll()
						  .anyRequest().authenticated()
			  )
			  .csrf(AbstractHttpConfigurer::disable)
			  .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
			  .addFilterBefore(sameDeviceAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
			  .addFilterBefore(crossDeviceAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
			  .formLogin(f->f.successHandler(new SuccessfulLoginAuthentication(issuerConfig.getServiceURL())))
			  .exceptionHandling(ex ->
					ex
						  .accessDeniedHandler((request, response, accessDeniedException) -> {
							  response.setStatus(HttpServletResponse.SC_FORBIDDEN);
							  response.getWriter().write("Access Denied");
						  })
						  .authenticationEntryPoint((request, response, authException) -> {
							  response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
							  response.getWriter().write("Unauthorized");
						  })
			  );
		logger.info("Setup the default security filter chain.");
		return http.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		logger.info("Setting up CORS Configuration.");
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(List.of("*"));
		configuration.setAllowedMethods(List.of("*"));
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setExposedHeaders(List.of("Location"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	/*@Bean
	public CustomUserDetailsService userDetailsService(UserRepository userRepository, UserTestLoginFormConfig userTest){
		if(!userTest.isEmpty()){
			User tester = new User(userTest.getFamilyName(), userTest.getGivenName(), userTest.getBirthDate(), userTest.getIssuingCountry(), userTest.getIssuanceAuthority(), userTest.getRole());
			tester.setPassword(userTest.getPassword());

			if(userRepository.findByHash(tester.getHash()).isEmpty())
				userRepository.save(tester);
		}
		return new CustomUserDetailsService(userRepository);
	}*/
	@Bean
	public CustomUserDetailsService userDetailsService(UserRepository userRepository){
		logger.info("Setting up UserDetailsService");
		logger.info(String.valueOf(userRepository.getClass()));
		return new CustomUserDetailsService(userRepository);
	}

	@Bean
	public AuthenticationManager authenticationManager(CustomUserDetailsService userDetailsService) {
		logger.info("Setting up authentication manager.");
		OID4VPAuthenticationProvider authenticationManagerProvider = new OID4VPAuthenticationProvider(userDetailsService);

		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		daoAuthenticationProvider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
		daoAuthenticationProvider.setHideUserNotFoundExceptions(true);

		List<AuthenticationProvider> providers = new ArrayList<>();
		providers.add(authenticationManagerProvider);
		logger.info("Added Provider: OID4VPAuthenticationProvider");
		providers.add(daoAuthenticationProvider);
		logger.info("Added Provider: DaoAuthenticationProvider");

		return new ProviderManager(providers);
	}

	@Bean
	public OID4VPAuthenticationSuccessHandler customAuthenticationSuccessHandler(SessionUrlRelationList sessionUrlRelationList){
		logger.info("Setting up OID4VPAuthenticationSuccessHandler");
		return new OID4VPAuthenticationSuccessHandler(sessionUrlRelationList);
	}

	@Bean
	public OID4VPAuthenticationFailureHandler customAuthenticationFailureHandler(){
		logger.info("Setting up OID4VPAuthenticationFailureHandler");
		return new OID4VPAuthenticationFailureHandler();
	}

	@Bean
	public OID4VPSameDeviceAuthenticationFilter authenticationFilter(
		AuthenticationManager authenticationManager, OID4VPAuthenticationSuccessHandler authenticationSuccessHandler,
		OID4VPAuthenticationFailureHandler authenticationFailureHandler, VerifierClient verifierClient,
		OpenIdForVPService oid4vpService, SessionUrlRelationList sessionUrlRelationList){

		OID4VPSameDeviceAuthenticationFilter filter = new OID4VPSameDeviceAuthenticationFilter(authenticationManager, verifierClient, oid4vpService, sessionUrlRelationList);
		filter.setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
		filter.setAuthenticationFailureHandler(authenticationFailureHandler);
		logger.info("Setting up OID4VPSameDeviceAuthenticationFilter");
		return filter;
	}

	@Bean
	public OID4VPCrossDeviceAuthenticationFilter crossDeviceAuthenticationFilter(
		  AuthenticationManager authenticationManager, OID4VPAuthenticationSuccessHandler authenticationSuccessHandler,
		  OID4VPAuthenticationFailureHandler authenticationFailureHandler, VerifierClient verifierClient,
		  OpenIdForVPService oid4vpService, SessionUrlRelationList sessionUrlRelationList){

		OID4VPCrossDeviceAuthenticationFilter filter = new OID4VPCrossDeviceAuthenticationFilter(authenticationManager, verifierClient, oid4vpService, sessionUrlRelationList);
		filter.setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
		filter.setAuthenticationFailureHandler(authenticationFailureHandler);
		logger.info("Setting up OID4VPCrossDeviceAuthenticationFilter");
		return filter;
	}
}
