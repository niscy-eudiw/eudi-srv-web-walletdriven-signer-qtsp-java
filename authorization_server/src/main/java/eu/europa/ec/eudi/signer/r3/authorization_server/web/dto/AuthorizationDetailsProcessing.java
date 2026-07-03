package eu.europa.ec.eudi.signer.r3.authorization_server.web.dto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;

import java.util.List;
import java.util.Map;

public class AuthorizationDetailsProcessing {

	public static List<AuthorizationDetails> parse(String authorizationDetails) throws JsonProcessingException {
		ObjectMapper mapper = new ObjectMapper();

		return mapper.readValue(
			  authorizationDetails, new TypeReference<>() {}
		);
	}

	public static List<AuthorizationDetails> fromAdditionalParameters(Map<String, Object> params) throws JsonProcessingException {
		return AuthorizationDetailsProcessing.parse(params.get(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS).toString());
	}
}



