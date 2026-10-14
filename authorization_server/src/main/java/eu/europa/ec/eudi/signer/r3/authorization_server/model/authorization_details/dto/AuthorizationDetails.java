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

public abstract class AuthorizationDetails {

	private final String type;

	protected AuthorizationDetails(JSONObject json){
		this.type = json.getString(OAuth2AuthorizationDetailsNames.TYPE);
	}

	public String getType() {
		return type;
	}

	public abstract void validate() throws AuthorizationDetailsException;

	/** Inverse of {@link #fromJson(JSONObject)}; null fields are omitted. */
	public JSONObject toJson() {
		return new JSONObject().put(OAuth2AuthorizationDetailsNames.TYPE, type);
	}

	protected static void require(boolean condition, String message) throws AuthorizationDetailsException {
		if (!condition) throw new AuthorizationDetailsException(message);
	}
	
	public static AuthorizationDetails fromJson(JSONObject json) throws AuthorizationDetailsException {
		if (OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL.contains(json.getString(OAuth2AuthorizationDetailsNames.TYPE))){
			return new CredentialAuthorizationDetails(json);
		}
		else if (OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_CREATION.contains(json.getString(OAuth2AuthorizationDetailsNames.TYPE))){
			return new CredentialCreationAuthorizationDetails(json);
		}
		else if (OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_DELETE.contains(json.getString(OAuth2AuthorizationDetailsNames.TYPE))){
			return new CredentialDeletionAuthorizationDetails(json);
		}
		else{
			throw new AuthorizationDetailsException("The 'type' in the 'authorization_details' parameter is invalid: " + json.getString(OAuth2AuthorizationDetailsNames.TYPE));
		}
	}

	
}
