/*
 Copyright 2025 European Commission

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

	public RegisteredClientAuthenticationForm(String id, String clientId, int authenticationFormId) {
		this.id = id;
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
