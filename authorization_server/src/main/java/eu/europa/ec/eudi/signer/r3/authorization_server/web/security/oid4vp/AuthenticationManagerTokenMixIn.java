package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.*;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = AuthenticationManagerTokenDeserializer.class)
@JsonAutoDetect(
      fieldVisibility = JsonAutoDetect.Visibility.ANY,
      getterVisibility = JsonAutoDetect.Visibility.NONE,
      isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class AuthenticationManagerTokenMixIn {
}


class AuthenticationManagerTokenDeserializer extends JsonDeserializer<AuthenticationManagerToken> {

    private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<>() {
    };

    private static final TypeReference<Object> OBJECT = new TypeReference<>() {
    };

    @Override
    public AuthenticationManagerToken deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);
        return deserialize(parser, mapper, root);
    }

    private AuthenticationManagerToken deserialize(JsonParser parser, ObjectMapper mapper, JsonNode root)
          throws IOException {
        boolean authenticated = readJsonNode(root, "authenticated").asBoolean();

        String hash = readJsonNode(root, "hash").asText();
        String username = readJsonNode(root, "username").asText();
        String scope = readJsonNode(root, "scope").asText();

        JsonNode principalNode = readJsonNode(root, "principal");
        Object principal = getPrincipal(mapper, principalNode);

        List<GrantedAuthority> authorities = mapper.readValue(readJsonNode(root, "authorities").traverse(mapper), GRANTED_AUTHORITY_LIST);

        AuthenticationManagerToken token = (!authenticated)
              ? AuthenticationManagerToken.unauthenticated(hash, username)
              : AuthenticationManagerToken.authenticated(principal, authorities);

        token.setScope(scope);
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
