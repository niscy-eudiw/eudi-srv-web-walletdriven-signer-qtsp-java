package eu.europa.ec.eudi.signer.r3.authorization_server.web.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OID4VPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.converter._AuthorizationRequestConverter;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.converter._TokenRequestConverter;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.provider.AuthorizationRequestProvider;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.provider.AuthorizationRequestProviderAfterAuthentication;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.provider._TokenRequestProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;

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
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

		_AuthorizationRequestConverter authorizationRequestConverter = new _AuthorizationRequestConverter();
		AuthorizationRequestProvider authorizationRequestProvider = new AuthorizationRequestProvider(registeredClientRepository, oid4VPService);
		CustomAuthenticationSuccessSecondHandler authenticationSuccessHandler = new CustomAuthenticationSuccessSecondHandler();

		_TokenRequestConverter tokenRequestConverter = new _TokenRequestConverter();
		_TokenRequestProvider tokenRequestProvider = new _TokenRequestProvider(authorizationService, tokenGenerator);

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
				.redirectUri("http://localhost:8080/authorized")
				.scope("service")
				.scope("credential")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
				.build();

		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		registeredClientRepository.save(scaClient);
		return registeredClientRepository;
	}

	@Bean
	public JdbcOAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
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
	public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(
			jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

	// Defines the authorizationServerSetting used by OAuth2AuthorizationServerConfigurer
	// customizing configuration settings for the OAuth2 authorization server
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
	}

	@Bean
	public AuthorizationRequestProviderAfterAuthentication getProviderForAfterAuthentication(
		RegisteredClientRepository registeredClientRepository,
		JdbcOAuth2AuthorizationService authorizationService,
		AuthorizationServerSettings serverSettings){

		AuthorizationServerContext context = new CustomAuthorizationServerContext("http://localhost:9000", serverSettings);

		return new AuthorizationRequestProviderAfterAuthentication(
			registeredClientRepository,
			authorizationService,
			context);
	}

	private static final class CustomAuthorizationServerContext implements AuthorizationServerContext {
		private final String issuer;
		private final AuthorizationServerSettings authorizationServerSettings;

		private CustomAuthorizationServerContext(String issuer, AuthorizationServerSettings authorizationServerSettings) {
			this.issuer = issuer;
			this.authorizationServerSettings = authorizationServerSettings;
		}

		public String getIssuer() {
			return this.issuer;
		}

		public AuthorizationServerSettings getAuthorizationServerSettings() {
			return this.authorizationServerSettings;
		}
	}
}
