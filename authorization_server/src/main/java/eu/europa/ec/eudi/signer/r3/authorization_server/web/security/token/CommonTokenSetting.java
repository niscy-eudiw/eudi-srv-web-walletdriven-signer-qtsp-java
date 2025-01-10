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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Service
public class CommonTokenSetting {

	public void setCommonParameters(ICommonTokenStructure token, URI url){
		Map<String, String> queryValues = getQueryValues(url);

		String client_id = getClientIdFromOAuth2Request(queryValues);
		if(client_id != null) token.setClient_id(client_id);

		String redirect_uri = getRedirectUriFromOAuth2Request(queryValues);
		if(redirect_uri != null) token.setRedirect_uri(redirect_uri);

		String scope = getScopeFromOAuth2Request(queryValues);
		token.setScope(scope);

		String hashDocument = getHashDocumentFromOAuth2Request(queryValues);
		if(hashDocument != null) token.setHashDocument(hashDocument);

		String credentialId = getCredentialIDFromOAuth2Request(queryValues);
		if(credentialId != null) token.setCredentialID(credentialId);

		String hashAlgorithmOID = getHashAlgorithmOIDFromOAuth2Request(queryValues);
		if(hashAlgorithmOID != null) token.setHashAlgorithmOID(hashAlgorithmOID);

		String numSignatures = getNumSignaturesFromOAuth2Request(queryValues);
		if(numSignatures != null) token.setNumSignatures(numSignatures);

		String authorizationDetails = getAuthorizationDetailsFromOAuth2Request(queryValues);
		if(authorizationDetails != null) token.setAuthorization_details(authorizationDetails);
	}

	public Map<String, String> getQueryValues(URI url){
		String query = url.getRawQuery();

		Map<String, String> queryPairs = new HashMap<>();
		String[] pairs = query.split("&");
		for (String pair : pairs) {
			int idx = pair.indexOf("=");
			if(idx != -1) {
				String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
				String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
				queryPairs.put(key, value);
			}
		}

		return queryPairs;
	}

	private String getClientIdFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("client_id");
	}

	private String getRedirectUriFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("redirect_uri");
	}

	public String getScopeFromOAuth2Request(Map<String, String> queryPairs) {
		String scope = queryPairs.get("scope");
		if(scope == null && queryPairs.get("authorization_details") != null)
			scope = "credential";

		return scope;
	}

	private String getHashDocumentFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("hashes");
	}

	private String getCredentialIDFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("credentialID");
	}

	private String getHashAlgorithmOIDFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("hashAlgorithmOID");
	}

	private String getNumSignaturesFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("numSignatures");
	}

	private String getAuthorizationDetailsFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get("authorization_details");
	}

}
