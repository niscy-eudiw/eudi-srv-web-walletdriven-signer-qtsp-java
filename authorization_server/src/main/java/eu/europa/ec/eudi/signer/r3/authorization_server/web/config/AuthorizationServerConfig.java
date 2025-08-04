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

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.AuthenticationFlowEnum;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.OAuth2ClientRegistrationConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.ServiceURLConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.client_auth_form.RegisteredClientAuthenticationForm;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.client_auth_form.RegisteredClientAuthenticationFormRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.credentials.CredentialsService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.ManageOAuth2Authorization;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin.UsernamePasswordAuthenticationTokenExtended;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin.UsernamePasswordAuthenticationTokenExtendedMixIn;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.handler.OAuth2AuthorizationSuccessHandler;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.*;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.CryptoUtils;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipalMixIn;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.DataSourceConfig;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.converter.AuthorizationCodeRequestConverter;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.converter.TokenRequestConverter;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.provider.AuthorizationRequestProvider;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.provider.TokenRequestProvider;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.function.Consumer;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	private final CryptoUtils cryptoUtils;
	private final Logger logger = LoggerFactory.getLogger(AuthorizationServerConfig.class);

	public AuthorizationServerConfig(@Autowired CryptoUtils cryptoUtils) {
		this.cryptoUtils = cryptoUtils;
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, RegisteredClientRepository registeredClientRepository, OpenIdForVPService openIdForVPService,
																	  JdbcOAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, AuthorizationServerSettings authorizationServerSettings,
																	  ServiceURLConfig issuerConfig, SessionUrlRelationList sessionUrlRelationList, ManageOAuth2Authorization manageOAuth2Authorization,
																	  RegisteredClientAuthenticationFormRepository registeredClientAuthenticationFormRepository,
																	  CredentialsService credentialDatabase) throws Exception
	{
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
		authorizationServerConfigurer.oidc(Customizer.withDefaults());

		AuthorizationCodeRequestConverter authorizationRequestConverter = new AuthorizationCodeRequestConverter();
		AuthorizationRequestProvider authorizationRequestProvider = new AuthorizationRequestProvider(registeredClientRepository, authorizationService, manageOAuth2Authorization, credentialDatabase);
		TokenRequestConverter tokenRequestConverter = new TokenRequestConverter();
		TokenRequestProvider tokenRequestProvider = new TokenRequestProvider(authorizationService, tokenGenerator, credentialDatabase);

		authorizationServerConfigurer
			  .registeredClientRepository(registeredClientRepository)
			  .authorizationService(authorizationService)
			  .authorizationServerSettings(authorizationServerSettings)
			  .tokenGenerator(tokenGenerator)
			  .authorizationEndpoint(authorizationEndpoint ->
					authorizationEndpoint
						  .authorizationRequestConverter(authorizationRequestConverter)
						  .authenticationProvider(authorizationRequestProvider)
						  .authenticationProviders(removeDefaultAuthorizationCodeProvider())
						  .authorizationResponseHandler(new OAuth2AuthorizationSuccessHandler()))
			  .tokenEndpoint(tokenEndpoint ->
					tokenEndpoint
						  .accessTokenRequestConverter(tokenRequestConverter)
						  .authenticationProviders(removeDefaultTokenProvider())
						  .authenticationProvider(tokenRequestProvider));
		logger.info("Set up authorizationServerConfig.");

		String clientId = "client_id";

		http
			.exceptionHandling((exceptions) -> {
				OID4VPSameDeviceAuthenticationEntryPoint entryPoint = new OID4VPSameDeviceAuthenticationEntryPoint(openIdForVPService, issuerConfig, sessionUrlRelationList);
				RequestMatcher requestMatcherDefault = request -> {
					String client_id = request.getParameter(clientId);
					RegisteredClientAuthenticationForm authenticationForm = registeredClientAuthenticationFormRepository.findByClientId(client_id).orElseThrow();
					return authenticationForm.getAuthenticationFormId() == AuthenticationFlowEnum.SAME_DEVICE_FLOW.getId();
				};
				exceptions.defaultAuthenticationEntryPointFor(entryPoint, requestMatcherDefault);

				OID4VPCrossDeviceAuthenticationEntryPoint crossDeviceEntryPoint = new OID4VPCrossDeviceAuthenticationEntryPoint(issuerConfig, sessionUrlRelationList);
				RequestMatcher requestMatcherCrossDevice = request -> {
					String client_id = request.getParameter(clientId);
					RegisteredClientAuthenticationForm authenticationForm = registeredClientAuthenticationFormRepository.findByClientId(client_id).orElseThrow();
					return authenticationForm.getAuthenticationFormId() == AuthenticationFlowEnum.CROSS_DEVICE_FLOW.getId();
				};
				exceptions.defaultAuthenticationEntryPointFor(crossDeviceEntryPoint, requestMatcherCrossDevice);

				RequestMatcher requestMatcher = request -> {
					String client_id = request.getParameter(clientId);
					RegisteredClientAuthenticationForm authenticationForm = registeredClientAuthenticationFormRepository.findByClientId(client_id).orElseThrow();
					return authenticationForm.getAuthenticationFormId() == AuthenticationFlowEnum.LOGIN_FORM.getId();
				};
				exceptions.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint(issuerConfig.getServiceURL()+"/login"), requestMatcher);
			})
			.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()));
		logger.info("Set up the http exception handling and authentication methods.");
		return http.build();
	}

	private Consumer<List<AuthenticationProvider>> removeDefaultAuthorizationCodeProvider() {
		return (authenticationProviders) -> {
			authenticationProviders.removeIf(authenticationProvider -> authenticationProvider.getClass().equals(OAuth2AuthorizationCodeRequestAuthenticationProvider.class));
		};
	}

	private Consumer<List<AuthenticationProvider>> removeDefaultTokenProvider() {
		return (authenticationProviders) -> {
			authenticationProviders.removeIf(authenticationProvider -> authenticationProvider.getClass().equals(OAuth2AuthorizationCodeAuthenticationProvider.class));
		};
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings(ServiceURLConfig issuerConfig) {
		logger.info("Setting up AuthorizationServerSettings with Issuer URL {}", issuerConfig.getOauth2IssuerURL());
		return AuthorizationServerSettings.builder()
			  .issuer(issuerConfig.getOauth2IssuerURL())
			  .build();
	}

	@Bean
	public JdbcTemplate jdbcTemplate(DataSourceConfig dataSourceConfig){
		logger.info("Setting up JdbcTemplate with DataSource {}", dataSourceConfig.getDataSource());
		return new JdbcTemplate(dataSourceConfig.getDataSource());
	}

	// Defines the RegisteredClientRepository used by the OAuth2AuthorizationServerConfigurer
	// for managing new and existing clients
	@Bean
	public JdbcRegisteredClientRepository registeredClientRepository(OAuth2ClientRegistrationConfig config, JdbcTemplate jdbcTemplate,
																	 RegisteredClientAuthenticationFormRepository registeredClientExtendedRepository) {
		logger.info("Setting up JdbcRegisteredClientRepository");

		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

		for (Map.Entry<String, OAuth2ClientRegistrationConfig.Client> e : config.getClient().entrySet()) {
			OAuth2ClientRegistrationConfig.Client registration = e.getValue();
			RegisteredClient.Builder clientBuilder = RegisteredClient.withId(e.getKey())
				.clientId(registration.getClientId())
				.clientSecret(registration.getClientSecret())
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build());

			for (String clientAuthMethodValue: registration.getClientAuthenticationMethods()){
				ClientAuthenticationMethod clientAuthenticationMethod = new ClientAuthenticationMethod(clientAuthMethodValue);
				clientBuilder.clientAuthenticationMethod(clientAuthenticationMethod);
			}
			for (String authGrantTypeValue: registration.getAuthorizationGrantTypes()){
				AuthorizationGrantType authorizationGrantType = new AuthorizationGrantType(authGrantTypeValue);
				clientBuilder.authorizationGrantType(authorizationGrantType);
			}
			for (String redirectUri : registration.getRedirectUris())
				clientBuilder.redirectUri(redirectUri);
			for (String scope : registration.getScopes())
				clientBuilder.scope(scope);
			RegisteredClient client = clientBuilder.build();
			registeredClientRepository.save(client);

			RegisteredClientAuthenticationForm registeredClientAuthenticationForm = new RegisteredClientAuthenticationForm(client.getId(), client.getClientId(), registration.getAuthenticationFlow().getId());
			registeredClientExtendedRepository.save(registeredClientAuthenticationForm);
		}

		return registeredClientRepository;
	}

	@Bean
	public JdbcOAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
		JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
		JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper oAuth2AuthorizationParametersMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();

		ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.registerModules(securityModules);
		objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		objectMapper.addMixIn(OID4VPAuthenticationToken.class, OID4VPAuthenticationTokenMixIn.class);
		objectMapper.addMixIn(UserPrincipal.class, UserPrincipalMixIn.class);
		objectMapper.addMixIn(UsernamePasswordAuthenticationTokenExtended.class, UsernamePasswordAuthenticationTokenExtendedMixIn.class);

		rowMapper.setObjectMapper(objectMapper);
		oAuth2AuthorizationParametersMapper.setObjectMapper(objectMapper);
		authorizationService.setAuthorizationRowMapper(rowMapper);
		authorizationService.setAuthorizationParametersMapper(oAuth2AuthorizationParametersMapper);
		return authorizationService;
	}

	@Bean
	public ManageOAuth2Authorization manageOAuth2Authorization(JdbcTemplate jdbcTemplate){
		return new ManageOAuth2Authorization(jdbcTemplate);
	}

	// the JWK Set endpoint is configured only if a JWKSource<SecurityContext> @Bean is registered
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
			.privateKey(privateKey)
			.keyID(UUID.randomUUID().toString())
			.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(UserRepository userRepository) {
		logger.info("Setting up OAuth2TokenCustomizer");
		String credentialIdParameter = "credentialID";
		String hashAlgorithmOIDParameter = "hashAlgorithmOID";
		String numSignaturesParameter = "numSignatures";
		String hashesParameter = "hashes";

		return context -> {
			if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) return;

			JwtClaimsSet.Builder claims = context.getClaims();
			OAuth2Authorization authorization = context.getAuthorization();
			if (authorization == null) return;

			if(authorization.getAuthorizedScopes().contains("service")){
				if(context.getPrincipal().getClass().equals(OID4VPAuthenticationToken.class) || context.getPrincipal().getClass().equals(UsernamePasswordAuthenticationToken.class) || context.getPrincipal().getClass().equals(UsernamePasswordAuthenticationTokenExtended.class)){
					Authentication token = context.getPrincipal();
					addUserClaims(token, claims, userRepository);
				}
			}

			if (authorization.getAuthorizedScopes().contains("credential")) {
					OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
                    assert authorizationRequest != null;
                    if (authorizationRequest.getAdditionalParameters().get("authorization_details") != null) {
						String authDetailsAuthorization = URLDecoder.decode(authorizationRequest.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);
						JSONArray authDetailsAuthorizationArray = new JSONArray(authDetailsAuthorization);
						JSONObject authDetailsAuthorizationJSON = authDetailsAuthorizationArray.getJSONObject(0);

						JSONArray documentDigests = authDetailsAuthorizationJSON.getJSONArray("documentDigests");
						List<String> hashesList = new ArrayList<>();
						for (int i = 0; i < documentDigests.length(); i++) {
							JSONObject document = documentDigests.getJSONObject(i);
							String hashValue = document.getString("hash");
							hashesList.add(hashValue);
						}
						String hashes = String.join(",", hashesList);

						claims.claim(credentialIdParameter, authDetailsAuthorizationJSON.get(credentialIdParameter));
						claims.claim(hashAlgorithmOIDParameter, authDetailsAuthorizationJSON.get(hashAlgorithmOIDParameter));
						claims.claim(numSignaturesParameter, documentDigests.length());
						claims.claim(hashesParameter, hashes);
					} else {
						claims.claim(credentialIdParameter, authorizationRequest.getAdditionalParameters().get(credentialIdParameter).toString());
						claims.claim(numSignaturesParameter, authorizationRequest.getAdditionalParameters().get(numSignaturesParameter).toString());
						claims.claim(hashesParameter, authorizationRequest.getAdditionalParameters().get(hashesParameter).toString());
						claims.claim(hashAlgorithmOIDParameter, authorizationRequest.getAdditionalParameters().get(hashAlgorithmOIDParameter).toString());
					}
			}
		};
	}

	private void addUserClaims(Authentication token, JwtClaimsSet.Builder claims, UserRepository userRepository) {
		if(token.getPrincipal().getClass().equals(UserPrincipal.class)) {
			UserPrincipal up = (UserPrincipal) token.getPrincipal();
			claims.claim("givenName", this.cryptoUtils.encryptString(up.getGivenName()));
			claims.claim("surname", this.cryptoUtils.encryptString(up.getSurname()));
			User u = userRepository.findByHash(up.getUsername()).orElseThrow();
			claims.claim("issuingCountry", u.getIssuingCountry());
		}
	}

	private void addCredentialClaims(JwtClaimsSet.Builder claims, OAuth2Authorization authorization) {
		OAuth2AuthorizationRequest request = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		if (request == null) return;

		Map<String, Object> params = request.getAdditionalParameters();
		Object authDetails = params.get("authorization_details");

		if (authDetails != null) {
			JSONObject authDetailsJSON = new JSONArray(
				  URLDecoder.decode(authDetails.toString(), StandardCharsets.UTF_8))
				  .getJSONObject(0);

			claims.claim("credentialID", authDetailsJSON.get("credentialID"));
			claims.claim("hashAlgorithmOID", authDetailsJSON.get("hashAlgorithmOID"));

			JSONArray docs = authDetailsJSON.getJSONArray("documentDigests");
			List<String> hashes = new ArrayList<>();
			for (int i = 0; i < docs.length(); i++) {
				hashes.add(docs.getJSONObject(i).getString("hash"));
			}

			claims.claim("numSignatures", docs.length());
			claims.claim("hashes", String.join(",", hashes));
		} else {
			claims.claim("credentialID", params.get("credentialID").toString());
			claims.claim("numSignatures", params.get("numSignatures").toString());
			claims.claim("hashes", params.get("hashes").toString());
			claims.claim("hashAlgorithmOID", params.get("hashAlgorithmOID").toString());
		}
	}


	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource, OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(jwtCustomizer);
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		logger.info("Setting up OAuth2TokenGenerator");
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}
}
