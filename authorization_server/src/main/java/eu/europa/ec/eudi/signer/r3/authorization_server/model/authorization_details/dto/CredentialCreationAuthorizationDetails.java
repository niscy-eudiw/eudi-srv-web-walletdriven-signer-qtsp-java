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

import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.OAuth2AuthorizationDetailsNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.AuthorizationDetailsException;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.CredentialCreationRequest;

public class CredentialCreationAuthorizationDetails extends AuthorizationDetails {
	private final List<String> acrValues;
	private final CredentialCreationRequest credentialCreationRequest;

	public CredentialCreationAuthorizationDetails(JSONObject json) throws AuthorizationDetailsException {
		super(json);
		this.acrValues = json.getJSONArray(OAuth2AuthorizationDetailsNames.ACR_VALUES).toList().stream().map(Object::toString).toList();
		this.credentialCreationRequest = readCredentialCreationRequest(json);
	}

	private static CredentialCreationRequest readCredentialCreationRequest(JSONObject json) throws AuthorizationDetailsException {
		JSONObject requestJson = json.getJSONObject(OAuth2AuthorizationDetailsNames.CREDENTIAL_CREATION_REQUEST);
		if (requestJson == null) return null;
		CredentialCreationRequest request = new CredentialCreationRequest();
		request.setCertificatePolicy(requestJson.getString(OAuth2AuthorizationDetailsNames.CERTIFICATE_POLICY));
		request.setSubjectData(requestJson.getString(OAuth2AuthorizationDetailsNames.SUBJECT_DATA));
		return request;
	}

	@Override
	public void validate() throws AuthorizationDetailsException {
		require(credentialCreationRequest != null, "The 'credentialCreationRequest' in the 'authorization_details' parameter is missing.");
	}

	@Override
	public JSONObject toJson() {
		JSONObject json = super.toJson();
		json.putOpt(OAuth2AuthorizationDetailsNames.ACR_VALUES, acrValues == null ? null : new JSONArray(acrValues));
		if (credentialCreationRequest != null) {
			JSONObject requestJson = new JSONObject();
			requestJson.putOpt(OAuth2AuthorizationDetailsNames.CERTIFICATE_POLICY, credentialCreationRequest.getCertificatePolicy());
			requestJson.putOpt(OAuth2AuthorizationDetailsNames.SUBJECT_DATA, credentialCreationRequest.getSubjectData());
			json.put(OAuth2AuthorizationDetailsNames.CREDENTIAL_CREATION_REQUEST, requestJson);
		}
		return json;
	}

	public List<String> getAcrValues() {
		return acrValues;
	}

	public CredentialCreationRequest getCredentialCreationRequest() {
		return credentialCreationRequest;
	}

	@Override
	public String toString() {
		return "CredentialCreationAuthorizationDetails{" +
				"type='" + getType() + '\'' +
				", acrValues=" + acrValues +
				", credentialCreationRequest=" + credentialCreationRequest +
				'}';
	}
}
