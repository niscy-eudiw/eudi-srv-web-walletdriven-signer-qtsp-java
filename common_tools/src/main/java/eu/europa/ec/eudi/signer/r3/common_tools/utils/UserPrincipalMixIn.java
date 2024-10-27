package eu.europa.ec.eudi.signer.r3.common_tools.utils;

import java.io.IOException;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = UserPrincipalDeserializer.class)
@JsonAutoDetect(
      fieldVisibility = JsonAutoDetect.Visibility.ANY,
      getterVisibility = JsonAutoDetect.Visibility.NONE,
      isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class UserPrincipalMixIn {}


class UserPrincipalDeserializer extends JsonDeserializer<UserPrincipal> {
    private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<>() {};

    @Override
    public UserPrincipal deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);
        return deserialize(mapper, root);
    }

    private UserPrincipal deserialize(ObjectMapper mapper, JsonNode root)
          throws IOException {
        String id = readJsonNode(root, "id").asText();
        String hash = readJsonNode(root, "hash").asText();
        String givenName = readJsonNode(root, "givenName").asText();
        String surname = readJsonNode(root, "surname").asText();
        List<GrantedAuthority> authorities = mapper.readValue(readJsonNode(root, "authorities").traverse(mapper), GRANTED_AUTHORITY_LIST);
        String password = readJsonNode(root, "password").asText();
        return new UserPrincipal(id, hash, givenName, surname, authorities, password);
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}