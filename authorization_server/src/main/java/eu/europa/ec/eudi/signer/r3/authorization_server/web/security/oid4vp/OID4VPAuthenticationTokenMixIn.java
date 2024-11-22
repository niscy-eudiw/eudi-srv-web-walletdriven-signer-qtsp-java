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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.*;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = OID4VPAuthenticationTokenDeserializer.class)
@JsonAutoDetect(
      fieldVisibility = JsonAutoDetect.Visibility.ANY,
      getterVisibility = JsonAutoDetect.Visibility.NONE,
      isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class OID4VPAuthenticationTokenMixIn {
}


class OID4VPAuthenticationTokenDeserializer extends JsonDeserializer<OID4VPAuthenticationToken> {

    private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<>() {
    };

    private static final TypeReference<Object> OBJECT = new TypeReference<>() {
    };

    @Override
    public OID4VPAuthenticationToken deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);
        return deserialize(parser, mapper, root);
    }

    private OID4VPAuthenticationToken deserialize(JsonParser parser, ObjectMapper mapper, JsonNode root)
          throws IOException {
        boolean authenticated = readJsonNode(root, "authenticated").asBoolean();

        String hash = readJsonNode(root, "hash").asText();
        String username = readJsonNode(root, "username").asText();
        JsonNode principalNode = readJsonNode(root, "principal");
        Object principal = getPrincipal(mapper, principalNode);

        List<GrantedAuthority> authorities = mapper.readValue(readJsonNode(root, "authorities").traverse(mapper), GRANTED_AUTHORITY_LIST);

        OID4VPAuthenticationToken token = (!authenticated)
              ? OID4VPAuthenticationToken.unauthenticated(hash, username)
              : OID4VPAuthenticationToken.authenticated(principal, authorities);

        JsonNode client_id_node = readJsonNode(root, "client_id");
        if(!client_id_node.isMissingNode()) token.setClient_id(client_id_node.asText());

        JsonNode redirect_uri_node = readJsonNode(root, "redirect_uri");
        if(!redirect_uri_node.isMissingNode()) token.setRedirect_uri(redirect_uri_node.asText());

        JsonNode scope_node = readJsonNode(root, "scope");
        if(!scope_node.isMissingNode()) token.setScope(scope_node.asText());

        JsonNode hashDocument_node = readJsonNode(root, "hashDocument");
        if(!hashDocument_node.isMissingNode()) token.setHashDocument(hashDocument_node.asText());

        JsonNode credentialID_node = readJsonNode(root, "credentialID");
        if(!credentialID_node.isMissingNode()) token.setCredentialID(credentialID_node.asText());

        JsonNode hashAlgorithmOID_node = readJsonNode(root, "hashAlgorithmOID");
        if(!hashAlgorithmOID_node.isMissingNode()) token.setHashAlgorithmOID(hashAlgorithmOID_node.asText());

        JsonNode numSignatures_node = readJsonNode(root, "numSignatures");
        if(!numSignatures_node.isMissingNode()) token.setNumSignatures(numSignatures_node.asText());

        JsonNode authorization_details_node = readJsonNode(root, "authorization_details");
        if(!authorization_details_node.isMissingNode()) token.setAuthorization_details(authorization_details_node.asText());

        JsonNode detailsNode = readJsonNode(root, "details");
        if (detailsNode.isNull() || detailsNode.isMissingNode()) {
            token.setDetails(null);
        }
        else {
            Object details = mapper.readValue(detailsNode.toString(), OBJECT);
            token.setDetails(details);
        }
        return token;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }

    private Object getPrincipal(ObjectMapper mapper, JsonNode principalNode) throws IOException {
        if (principalNode.isObject()) return mapper.readValue(principalNode.traverse(mapper), Object.class);
        return principalNode.asText();
    }
}
