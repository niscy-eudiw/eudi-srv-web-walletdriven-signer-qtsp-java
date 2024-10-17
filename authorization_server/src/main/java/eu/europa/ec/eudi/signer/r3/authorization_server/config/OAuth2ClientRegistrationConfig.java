package eu.europa.ec.eudi.signer.r3.authorization_server.config;

import java.util.Map;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix="authorizationserver")
public class OAuth2ClientRegistrationConfig {

    private Map<String, Client> client;

    public Map<String, Client> getClient() {
        return client;
    }

    public void setClient(Map<String, Client> client) {
        this.client = client;
    }

    public static class Client {
        private Registration registration;

        public Registration getRegistration() {
            return registration;
        }

        public void setRegistration(Registration registration) {
            this.registration = registration;
        }
    }

    public static class Registration {
        private String clientId;
        private String clientSecret;
        private Set<String> clientAuthenticationMethods;
        private Set<String> authorizationGrantTypes;
        private Set<String> redirectUris;
        private Set<String> scopes;
        private boolean requireAuthorizationConsent;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public Set<String> getClientAuthenticationMethods() {
            return clientAuthenticationMethods;
        }

        public void setClientAuthenticationMethods(Set<String> clientAuthenticationMethods) {
            this.clientAuthenticationMethods = clientAuthenticationMethods;
        }

        public Set<String> getAuthorizationGrantTypes() {
            return authorizationGrantTypes;
        }

        public void setAuthorizationGrantTypes(Set<String> authorizationGrantTypes) {
            this.authorizationGrantTypes = authorizationGrantTypes;
        }

        public Set<String> getRedirectUris() {
            return redirectUris;
        }

        public void setRedirectUris(Set<String> redirectUris) {
            this.redirectUris = redirectUris;
        }

        public Set<String> getScopes() {
            return scopes;
        }

        public void setScopes(Set<String> scopes) {
            this.scopes = scopes;
        }

        public boolean isRequireAuthorizationConsent() {
            return requireAuthorizationConsent;
        }

        public void setRequireAuthorizationConsent(boolean requireAuthorizationConsent) {
            this.requireAuthorizationConsent = requireAuthorizationConsent;
        }
    }
}
