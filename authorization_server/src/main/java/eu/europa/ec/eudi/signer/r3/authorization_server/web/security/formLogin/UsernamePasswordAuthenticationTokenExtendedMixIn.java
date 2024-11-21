package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin;

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

import java.io.IOException;
import java.util.List;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = UsernamePasswordAuthenticationTokenExtendedDeserializer.class)
@JsonAutoDetect(
	  fieldVisibility = JsonAutoDetect.Visibility.ANY,
	  getterVisibility = JsonAutoDetect.Visibility.NONE,
	  isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class UsernamePasswordAuthenticationTokenExtendedMixIn {
}

class UsernamePasswordAuthenticationTokenExtendedDeserializer extends JsonDeserializer<UsernamePasswordAuthenticationTokenExtended> {

	private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<>() {
	};

	private static final TypeReference<Object> OBJECT = new TypeReference<>() {
	};

	@Override
	public UsernamePasswordAuthenticationTokenExtended deserialize(JsonParser parser, DeserializationContext context) throws IOException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode root = mapper.readTree(parser);
		return deserialize(parser, mapper, root);
	}

	private UsernamePasswordAuthenticationTokenExtended deserialize(JsonParser parser, ObjectMapper mapper, JsonNode root)
		  throws IOException {
		boolean authenticated = readJsonNode(root, "authenticated").asBoolean();

		JsonNode principalNode = readJsonNode(root, "principal");
		Object principal = getPrincipal(mapper, principalNode);

		JsonNode credentialsNode = readJsonNode(root, "credentials");
		Object credentials = getCredentials(credentialsNode);

		List<GrantedAuthority> authorities = mapper.readValue(readJsonNode(root, "authorities").traverse(mapper), GRANTED_AUTHORITY_LIST);

		UsernamePasswordAuthenticationTokenExtended token = (!authenticated)
			  ? new UsernamePasswordAuthenticationTokenExtended(principal, credentials)
			  : new UsernamePasswordAuthenticationTokenExtended(principal, credentials, authorities);

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

	private Object getCredentials(JsonNode credentialsNode) {
		if (credentialsNode.isNull() || credentialsNode.isMissingNode()) {
			return null;
		}
		return credentialsNode.asText();
	}



}