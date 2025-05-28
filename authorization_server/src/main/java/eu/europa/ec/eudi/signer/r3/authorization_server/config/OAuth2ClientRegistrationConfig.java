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
        private String clientId;
        private String clientSecret;
        private Set<String> redirectUris;
        private Set<String> scopes;
        private AuthenticationMethodEnum authenticationMethod;

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

        public AuthenticationMethodEnum getAuthenticationMethod() {
            return authenticationMethod;
        }

        public void setAuthenticationMethod(AuthenticationMethodEnum authenticationMethod) {
            this.authenticationMethod = authenticationMethod;
        }
    }
}
