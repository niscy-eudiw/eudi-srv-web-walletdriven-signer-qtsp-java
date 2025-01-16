package eu.europa.ec.eudi.signer.r3.authorization_server.model.client_auth_form;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

@Entity
@Table(name = "registered_client_authentication_form",
	  uniqueConstraints = @UniqueConstraint(columnNames = { "client_id", "authentication_form_id" }))
public class RegisteredClientAuthenticationForm{
	@Id
	private String id;
	@NotNull
	@Column(name = "client_id")
	private String clientId;
	@NotNull
	@Column(name = "authentication_form_id")
	private int authenticationFormId;

	public RegisteredClientAuthenticationForm() {
		this.id = UUID.randomUUID().toString();
	}

	public RegisteredClientAuthenticationForm(String clientId, int authenticationFormId) {
		this.id = UUID.randomUUID().toString();
		this.clientId = clientId;
		this.authenticationFormId = authenticationFormId;
	}

	public @NotNull String getClientId() {
		return clientId;
	}

	public void setClientId(@NotNull String clientId) {
		this.clientId = clientId;
	}

	public @NotNull int getAuthenticationFormId() {
		return authenticationFormId;
	}

	public void setAuthenticationFormId(@NotNull int authenticationFormId) {
		this.authenticationFormId = authenticationFormId;
	}
}
