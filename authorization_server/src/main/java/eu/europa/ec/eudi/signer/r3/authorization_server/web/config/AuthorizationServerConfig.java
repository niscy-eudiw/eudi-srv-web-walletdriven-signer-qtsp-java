package eu.europa.ec.eudi.signer.r3.authorization_server.web.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipalMixIn;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.DataSourceConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OID4VPService;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.*;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oauth2.converter.AuthorizationRequestConverter;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oauth2.converter.TokenRequestConverter;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oauth2.handler.CustomAuthenticationSuccessHandler;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oauth2.provider.AuthorizationRequestProvider;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oauth2.provider.TokenRequestProvider;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	private final OID4VPService oid4VPService;

	public AuthorizationServerConfig(@Autowired OID4VPService oid4VPService){
		this.oid4VPService = oid4VPService;
	}

	// private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";
	// OAuth2AuthorizationServerConfiguration is a configuration that provides the minimal default configuration
	// OAuth2AuthorizationServerConfiguration provides a convenient method to apply the minimal default configuration for an OAuth2 authorization server
	// This uses a OAuth2AuthorizationServerConfigurer
	// "applyDefaultSecurity" is a convinence utility method that applies the default security configuration to HttpSecurity
	// OAuth2AuthorizationServerConfigurer provides the ability to fully customize the security configuration for an OAuth2 authorization server
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(
		HttpSecurity http,
		RegisteredClientRepository registeredClientRepository,
		JdbcOAuth2AuthorizationService authorizationService,
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
		OID4VPAuthenticationFilter authenticationFilter) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

		AuthorizationRequestConverter authorizationRequestConverter = new AuthorizationRequestConverter();
		AuthorizationRequestProvider authorizationRequestProvider = new AuthorizationRequestProvider(registeredClientRepository, authorizationService);
		CustomAuthenticationSuccessHandler authenticationSuccessHandler = new CustomAuthenticationSuccessHandler();

		TokenRequestConverter tokenRequestConverter = new TokenRequestConverter();
		TokenRequestProvider tokenRequestProvider = new TokenRequestProvider(authorizationService, tokenGenerator);

		authorizationServerConfigurer
			.authorizationEndpoint(authorizationEndpoint ->
				authorizationEndpoint
					.authorizationRequestConverter(authorizationRequestConverter)
					.authenticationProvider(authorizationRequestProvider)
					.authorizationResponseHandler(authenticationSuccessHandler))
			.tokenEndpoint(tokenEndpoint ->
				tokenEndpoint
					.accessTokenRequestConverter(tokenRequestConverter)
					.authenticationProvider(tokenRequestProvider));

		http
			.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
			.exceptionHandling((exceptions) -> {
					OID4VPAuthenticationEntryPoint entryPoint = new OID4VPAuthenticationEntryPoint(oid4VPService);
					RequestMatcher requestMatcher = request -> true;
					exceptions.defaultAuthenticationEntryPointFor(entryPoint, requestMatcher);
				}
			)
			.oauth2ResourceServer(oauth2ResourceServer ->
				oauth2ResourceServer.jwt(Customizer.withDefaults()));
		return http.build();
	}

	// Defines the RegisteredClientRepository used by the OAuth2AuthorizationServerConfigurer
	// for managing new and existing clients
	@Bean
	public JdbcRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		RegisteredClient scaClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("sca-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(new AuthorizationGrantType("code"))
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("http://localhost:8080/login/oauth2/code/sca-client")
				.scope("service")
				.scope("credential")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
				.build();

		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		if(registeredClientRepository.findByClientId("sca-client") == null)
			registeredClientRepository.save(scaClient);
		return registeredClientRepository;
	}

	@Bean
	public JdbcTemplate jdbcTemplate(DataSourceConfig dataSourceConfig){
		return new JdbcTemplate(dataSourceConfig.getDataSource());
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
		objectMapper.addMixIn(AuthenticationManagerToken.class, AuthenticationManagerTokenMixIn.class);
		objectMapper.addMixIn(UserPrincipal.class, UserPrincipalMixIn.class);

		rowMapper.setObjectMapper(objectMapper);
		oAuth2AuthorizationParametersMapper.setObjectMapper(objectMapper);
		authorizationService.setAuthorizationRowMapper(rowMapper);
		authorizationService.setAuthorizationParametersMapper(oAuth2AuthorizationParametersMapper);
		return authorizationService;
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
	public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource, OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(jwtCustomizer);
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

	// Defines the authorizationServerSetting used by OAuth2AuthorizationServerConfigurer
	// customizing configuration settings for the OAuth2 authorization server
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return context -> {
			JwsHeader.Builder headers = context.getJwsHeader();
			JwtClaimsSet.Builder claims = context.getClaims();

			System.out.println(context.getPrincipal().getPrincipal().getClass());
			System.out.println(context.getClass().getName());

			if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {

				OAuth2Authorization authorization = context.getAuthorization();
				OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

				// Customize headers/claims for access_token
				claims.claim("credentialID", "some_credential_id");

				if (authorization.getAuthorizedScopes().contains("credential")) {
					System.out.println("here");

					if (authorizationRequest.getAdditionalParameters().get("authorization_details") != null) {
						String authDetailsAuthorization = URLDecoder.decode(authorizationRequest.getAdditionalParameters().get("authorization_details").toString(), StandardCharsets.UTF_8);
						JSONObject authDetailsAuthorizationJSON = new JSONObject(authDetailsAuthorization);
						claims.claim("credentialID", authDetailsAuthorizationJSON.get("credentialID"));
						claims.claim("hashAlgorithmOID", authDetailsAuthorizationJSON.get("hashAlgorithmOID"));
						JSONArray documentDigests = authDetailsAuthorizationJSON.getJSONArray("documentDigests");
						List<String> hashesList = new ArrayList<>();
						for (int i = 0; i < documentDigests.length(); i++) {
							JSONObject document = documentDigests.getJSONObject(i);
							String hashValue = document.getString("hash");
							hashesList.add(hashValue);
						}
						String hashes = String.join(",", hashesList);
						claims.claim("numSignatures", documentDigests.length());
						claims.claim("hashes", hashes);
					} else {
						claims.claim("credentialID", authorizationRequest.getAdditionalParameters().get("credentialID").toString());
						claims.claim("numSignatures", authorizationRequest.getAdditionalParameters().get("numSignatures").toString());
						claims.claim("hashes", authorizationRequest.getAdditionalParameters().get("hashes").toString());
						claims.claim("hashAlgorithmOID", authorizationRequest.getAdditionalParameters().get("hashAlgorithmOID").toString());
					}
				}
			}
		};
	}
}
