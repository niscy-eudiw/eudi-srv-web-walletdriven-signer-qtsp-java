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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.OAuth2AuthorizationDetailsNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.AuthorizationDetailsException;

public class CredentialAuthorizationDetails extends AuthorizationDetails {
	private final List<String> locations;
	private String credentialId;
	private String signatureQualifier;
	private final Object numSignatures;
	private final String hashAlgorithmOid;
	private final List<DocumentDigest> documentDigests;

	public CredentialAuthorizationDetails(JSONObject json) throws AuthorizationDetailsException {
		super(json);
		JSONArray locationsArray = json.optJSONArray(OAuth2AuthorizationDetailsNames.LOCATIONS);
		this.locations = locationsArray == null ? null : locationsArray.toList().stream().map(Object::toString).collect(Collectors.toList());
		this.credentialId = json.optString(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID, null);
		this.signatureQualifier = json.optString(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER, null);
		Object numSignaturesValue = json.opt(OAuth2AuthorizationDetailsNames.NUM_SIGNATURES);
		this.numSignatures = JSONObject.NULL.equals(numSignaturesValue) ? null : numSignaturesValue;
		this.hashAlgorithmOid = json.optString(OAuth2AuthorizationDetailsNames.HASH_ALGORITHM_OID, null);
		this.documentDigests = readDocumentDigests(json);
	}

	private static List<DocumentDigest> readDocumentDigests(JSONObject json) throws AuthorizationDetailsException {
		JSONArray array = json.optJSONArray(OAuth2AuthorizationDetailsNames.DOCUMENT_DIGESTS);
		if (array == null) return List.of();
		List<DocumentDigest> digests = new ArrayList<>();
		for (int i = 0; i < array.length(); i++) {
			digests.add(new DocumentDigest(array.getJSONObject(i)));
		}
		return digests;
	}

	@Override
	public void validate() throws AuthorizationDetailsException {
		require(credentialId != null || signatureQualifier != null,
				"The 'credentialID' and 'signatureQualifier' in the 'authorization_details' parameter are both missing.");
		require(hashAlgorithmOid != null,
				"The 'hashAlgorithmOID' in the 'authorization_details' parameter is missing.");
		require(!documentDigests.isEmpty(),
				"The 'documentDigests' in the 'authorization_details' parameter is missing.");
		for (DocumentDigest documentDigest : documentDigests) {
			require(documentDigest.getHash() != null,
					"The 'hash' in 'documentDigests' within 'authorization_details' is missing.");
		}
		require(numSignatures != null,
				"The 'numSignatures' in the 'authorization_details' parameter is missing.");
		require(parsePositiveInt(numSignatures.toString()) != null,
				"The 'numSignatures' in the 'authorization_details' parameter must be a positive integer.");
	}

	private static Integer parsePositiveInt(String value) {
		try {
			int parsed = Integer.parseInt(value.trim());
			return parsed > 0 ? parsed : null;
		} catch (NumberFormatException e) {
			return null;
		}
	}

	@Override
	public JSONObject toJson() {
		JSONObject json = super.toJson();
		json.putOpt(OAuth2AuthorizationDetailsNames.LOCATIONS, locations == null ? null : new JSONArray(locations));
		json.putOpt(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID, credentialId);
		json.putOpt(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER, signatureQualifier);
		json.putOpt(OAuth2AuthorizationDetailsNames.NUM_SIGNATURES, numSignatures);
		json.putOpt(OAuth2AuthorizationDetailsNames.HASH_ALGORITHM_OID, hashAlgorithmOid);
		if (!documentDigests.isEmpty()) {
			JSONArray digests = new JSONArray();
			for (DocumentDigest documentDigest : documentDigests) {
				digests.put(documentDigest.toJSONObject());
			}
			json.put(OAuth2AuthorizationDetailsNames.DOCUMENT_DIGESTS, digests);
		}
		return json;
	}

	public List<String> getLocations() {
		return locations;
	}

	public String getCredentialId() {
		return credentialId;
	}

	public void setCredentialId(String credentialId) {
		this.credentialId = credentialId;
	}

	public String getSignatureQualifier() {
		return signatureQualifier;
	}

	public void removeSignatureQualifier() {
		this.signatureQualifier = null;
	}

	public String getNumSignatures() {
		return numSignatures == null ? null : numSignatures.toString().trim();
	}

	public String getHashAlgorithmOid() {
		return hashAlgorithmOid;
	}

	public List<DocumentDigest> getDocumentDigests() {
		return documentDigests;
	}

	@Override
	public String toString() {
		return "CredentialAuthorizationDetails{" +
				"type='" + getType() + '\'' +
				", locations=" + locations +
				", credentialId='" + credentialId + '\'' +
				", signatureQualifier='" + signatureQualifier + '\'' +
				", numSignatures='" + numSignatures + '\'' +
				", hashAlgorithmOid='" + hashAlgorithmOid + '\'' +
				", documentDigests=" + documentDigests +
				'}';
	}
}
