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

import org.json.JSONArray;
import org.json.JSONObject;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.OAuth2AuthorizationDetailsNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.AuthorizationDetailsException;

public class DocumentDigest {
	private final String label;
	private final String hash;
	private String hashType;
	private final JSONArray signedProps;
	private final String circumstantialData;

	public DocumentDigest(JSONObject json) throws AuthorizationDetailsException {
		this.label = json.optString("label", null);
		this.hash = json.optString(OAuth2AuthorizationDetailsNames.HASH, null);
		this.hashType = json.optString(OAuth2AuthorizationDetailsNames.HASH_TYPE, null);
		this.signedProps = json.optJSONArray(OAuth2AuthorizationDetailsNames.SIGNED_PROPS);
		this.circumstantialData = json.optString(OAuth2AuthorizationDetailsNames.CIRCUMSTANTIAL_DATA, null);
	}

	public DocumentDigest(String label, String hash) {
		this.label = label;
		this.hash = hash;
		this.hashType = null;
		this.signedProps = null;
		this.circumstantialData = null;
	}

	public JSONObject toJSONObject() {
		JSONObject json = new JSONObject();
		json.putOpt("label", label);
		json.putOpt(OAuth2AuthorizationDetailsNames.HASH, hash);
		json.putOpt(OAuth2AuthorizationDetailsNames.HASH_TYPE, hashType);
		json.putOpt(OAuth2AuthorizationDetailsNames.SIGNED_PROPS, signedProps);
		json.putOpt(OAuth2AuthorizationDetailsNames.CIRCUMSTANTIAL_DATA, circumstantialData);
		return json;
	}

	public String getLabel() {
		return label;
	}

	public String getHash() {
		return hash;
	}

	public String getHashType() {
		return hashType;
	}

	public void setHashType(String hashType) {
		this.hashType = hashType;
	}

	public JSONArray getSignedProps() {
		return signedProps;
	}

	public String getCircumstantialData() {
		return circumstantialData;
	}

	@Override
	public String toString() {
		return toJSONObject().toString();
	}

	private static final ObjectMapper MAPPER = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);

	public JSONObject toJSON() throws Exception {
		return new JSONObject(MAPPER.writeValueAsString(this));
	}
}
