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

import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2AuthorizationDetailsNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2ScopesNames;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
		return queryPairs.get(OAuth2ParameterNames.CLIENT_ID);
	}

	private String getRedirectUriFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get(OAuth2ParameterNames.REDIRECT_URI);
	}

	public String getScopeFromOAuth2Request(Map<String, String> queryPairs) {
		String scope = queryPairs.get(OAuth2ParameterNames.SCOPE);
		if(scope == null && queryPairs.get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS) != null){
			String authorizationDetails = queryPairs.get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS);
			JSONArray authorizationDetailsJson = new JSONArray(authorizationDetails);
			JSONObject firstAuthorizationDetail = authorizationDetailsJson.getJSONObject(0);
			String type = firstAuthorizationDetail.getString(OAuth2AuthorizationDetailsNames.TYPE);
			if(OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_CREATION.contains(type))
				scope = OAuth2ScopesNames.CREDENTIAL_CREATION;
			else if (OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_DELETE.contains(type))
				scope = OAuth2ScopesNames.CREDENTIAL_DELETION;
			else scope = OAuth2ScopesNames.CREDENTIAL;
		}
		return scope;
	}

	private String getHashDocumentFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get(OAuth2CustomParameterNames.HASHES);
	}

	private String getCredentialIDFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get(OAuth2CustomParameterNames.CREDENTIAL_ID);
	}

	private String getHashAlgorithmOIDFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get(OAuth2CustomParameterNames.HASH_ALGORITHM_OID);
	}

	private String getNumSignaturesFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get(OAuth2CustomParameterNames.NUM_SIGNATURES);
	}

	private String getAuthorizationDetailsFromOAuth2Request(Map<String, String> queryPairs){
		return queryPairs.get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS);
	}
}
