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

import eu.europa.ec.eudi.signer.r3.authorization_server.config.OAuth2IssuerConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.UserTestLoginFormConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.SuccessfulLoginAuthentication;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.*;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.handler.OID4VPAuthenticationFailureHandler;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.handler.OID4VPAuthenticationSuccessHandler;
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
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.util.ArrayList;
import java.util.List;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, OAuth2IssuerConfig issuerConfig) throws Exception {
		http
			.authorizeHttpRequests(authorize ->
				authorize
					.requestMatchers("/oid4vp/callback").permitAll()
					.requestMatchers("/login").permitAll()
					.anyRequest().authenticated()
			)
			.csrf(AbstractHttpConfigurer::disable)
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
			.formLogin(f->f.successHandler(new SuccessfulLoginAuthentication(issuerConfig.getUrl())));
		return http.build();
	}

	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	@Bean
	public CustomUserDetailsService userDetailsService(UserRepository userRepository, UserTestLoginFormConfig userTest){
		User tester = new User(userTest.getFamilyName(), userTest.getGivenName(), userTest.getBirthDate(), userTest.getIssuingCountry(), userTest.getIssuanceAuthority(), userTest.getRole());
		tester.setPassword(userTest.getPassword());
		if(userRepository.findByHash(tester.getHash()).isEmpty())
			userRepository.save(tester);
		return new CustomUserDetailsService(userRepository);
	}

	@Bean
	public AuthenticationManager authenticationManager(CustomUserDetailsService userDetailsService) {
		AuthenticationManagerProvider authenticationManagerProvider = new AuthenticationManagerProvider(userDetailsService);

		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		daoAuthenticationProvider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());

		List<AuthenticationProvider> providers = new ArrayList<>();
		providers.add(authenticationManagerProvider);
		providers.add(daoAuthenticationProvider);

		return new ProviderManager(providers);
	}

	@Bean
	public OID4VPAuthenticationSuccessHandler customAuthenticationSuccessHandler(SessionUrlRelationList sessionUrlRelationList){
		return new OID4VPAuthenticationSuccessHandler(sessionUrlRelationList);
	}

	@Bean
	public OID4VPAuthenticationFailureHandler customAuthenticationFailureHandler(){
		return new OID4VPAuthenticationFailureHandler();
	}

	@Bean
	public OID4VPAuthenticationFilter authenticationFilter(
		AuthenticationManager authenticationManager, OID4VPAuthenticationSuccessHandler authenticationSuccessHandler,
		OID4VPAuthenticationFailureHandler authenticationFailureHandler, VerifierClient verifierClient,
		OpenIdForVPService oid4vpService, SessionUrlRelationList sessionUrlRelationList){

		OID4VPAuthenticationFilter filter = new OID4VPAuthenticationFilter(authenticationManager, verifierClient, oid4vpService, sessionUrlRelationList);
		filter.setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
		filter.setAuthenticationFailureHandler(authenticationFailureHandler);
		return filter;
	}
}
