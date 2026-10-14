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
package eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.dto.AuthorizationDetails;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.AuthorizationDetailsException;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2ScopesNames;

public final class AuthorizationDetailsParser {

    private AuthorizationDetailsParser() {
    }

    public static List<AuthorizationDetails> parse(String authorizationDetails) throws AuthorizationDetailsException {
        JSONArray array = toJsonArray(authorizationDetails);
        List<AuthorizationDetails> result = new ArrayList<>();
        try {
            for (int i = 0; i < array.length(); i++) {
                JSONObject entry = array.getJSONObject(i);
                AuthorizationDetails authorizationDetailsEntry = AuthorizationDetails.fromJson(entry);
                result.add(authorizationDetailsEntry);
            }
        } catch (JSONException e) {
            throw new AuthorizationDetailsException("The 'authorization_details' parameter in the request is invalid: " + e.getMessage(), e);
        }
        return result;
    }

    /**
     * Inverse of {@link #parse(String)}: writes the entries back as a JSON
     * array string. Fields the typed model doesn't know are not included.
     */
    public static String serialize(List<? extends AuthorizationDetails> authorizationDetails) {
        JSONArray array = new JSONArray();
        for (AuthorizationDetails entry : authorizationDetails) {
            array.put(entry.toJson());
        }
        return array.toString();
    }

    /**
     * Type of the first entry, or empty if the value is missing or malformed.
     * Never throws: meant for request matching and scope resolution, where
     * errors are reported later by the validator.
     */
    public static String peekType(String authorizationDetails) {
        try {
            JSONArray array = toJsonArray(authorizationDetails);
            JSONObject firstEntry = array.optJSONObject(0);
            if (firstEntry == null) {
                throw new AuthorizationDetailsException("The 'authorization_details' parameter in the request is invalid.");
            }
            return typeOf(firstEntry);
        } catch (AuthorizationDetailsException e) {
            return null;
        }
    }

    /**
     * Reads the raw value as a non-empty JSON array, keeping every field
     * (including those the typed model doesn't know). Each call returns a new
     * array, so callers may modify it.
     */
    public static JSONArray toJsonArray(String authorizationDetails) throws AuthorizationDetailsException {
        if (authorizationDetails == null || authorizationDetails.isBlank()) {
            throw new AuthorizationDetailsException("Authorization Details object is missing.");
        }

        try {
            JSONArray array = new JSONArray(authorizationDetails);
            if (array.isEmpty()) {
                throw new AuthorizationDetailsException("Authorization Details object is missing.");
            }
            return array;
        } catch (JSONException e) {
            throw new AuthorizationDetailsException("The 'authorization_details' parameter in the request is invalid.", e);
        }
    }

    static String typeOf(JSONObject entry) throws AuthorizationDetailsException {
        String type = (String) entry.opt(OAuth2AuthorizationDetailsNames.TYPE);
        if (!(type instanceof String)) {
            throw new AuthorizationDetailsException("The 'type' in the 'authorization_details' parameter is missing.");
        }

        if (OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL.contains(type)) {
            return OAuth2ScopesNames.CREDENTIAL;
        } else if (OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_CREATION.contains(type)) {
            return OAuth2ScopesNames.CREDENTIAL_CREATION;
        } else if (OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_DELETE.contains(type)) {
            return OAuth2ScopesNames.CREDENTIAL_DELETION;
        }
        return type;
    }
}
