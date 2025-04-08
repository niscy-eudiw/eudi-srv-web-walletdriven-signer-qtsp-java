package eu.europa.ec.eudi.signer.r3.authorization_server.model.client_auth_form;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;

import java.util.Optional;

@Repository
public interface RegisteredClientAuthenticationFormRepository extends JpaRepository<RegisteredClientAuthenticationForm, String> {

	Optional<RegisteredClientAuthenticationForm> findByClientId(String clientId);
}
