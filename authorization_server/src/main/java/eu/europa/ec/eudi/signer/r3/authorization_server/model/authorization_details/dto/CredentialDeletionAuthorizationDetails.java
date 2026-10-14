/*
 Copyright 2026 European Commission

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

package eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.dto;

import org.json.JSONObject;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.OAuth2AuthorizationDetailsNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.AuthorizationDetailsException;


public class CredentialDeletionAuthorizationDetails extends AuthorizationDetails {
	private final String credentialId;

	public CredentialDeletionAuthorizationDetails(JSONObject json) throws AuthorizationDetailsException {
		super(json);
		this.credentialId = json.getString(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID);
	}

	@Override
	public void validate() throws AuthorizationDetailsException {
		require(credentialId != null, "The 'credentialID' in the 'authorization_details' parameter is missing for credential_deletion.");
	}

	@Override
	public JSONObject toJson() {
		return super.toJson().putOpt(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID, credentialId);
	}

	public String getCredentialId() {
		return credentialId;
	}

	@Override
	public String toString() {
		return "CredentialDeletionAuthorizationDetails{" +
					"type='" + getType() + '\'' + ", credentialId='" + credentialId + '\'' +
				'}';
	}
}
