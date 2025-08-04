package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPException;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2AuthorizeRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError.FAILED_TO_VALIDATE_TRANSACTION_DATA;

@Component
public class TransactionDataService {
	public static final String PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID = "eu.europa.ec.eudi.pid.1";
	private static final Logger logger = LoggerFactory.getLogger(TransactionDataService.class);

	public JSONArray getTransactionData(String oauth2AuthorizeRequestUrl) throws URISyntaxException {
		URI url = new URI(oauth2AuthorizeRequestUrl);
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(url);
		return getTransactionDataFromRequest(authorizeRequest);
	}

	public JSONArray getTransactionData(HttpServletRequest request){
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(request);
		return getTransactionDataFromRequest(authorizeRequest);
	}

	private JSONArray getTransactionDataFromRequest(OAuth2AuthorizeRequest authorizeRequest){
		logger.info("Creating TransactionData for Request: {}", authorizeRequest);
		if(authorizeRequest.getScope().equals("credential")){
			if(authorizeRequest.getAuthorization_details() != null){
				String authorizationDetails = authorizeRequest.getAuthorization_details();
				return getTransactionDataFromAuthorizationDetails(authorizationDetails);
			}
			else{
				String credentialId = authorizeRequest.getCredentialID();
				String signatureQualifier = authorizeRequest.getSignatureQualifier();
				String hashes = authorizeRequest.getHashes();
				String hashAlgorithmOID = authorizeRequest.getHashAlgorithmOID();
				String description = authorizeRequest.getDescription();
				JSONArray documentDigests = getArrayDocumentDigest(hashes, description);
				return getTransactionData(credentialId, hashAlgorithmOID, documentDigests);
			}
		}
		return null;
	}

	private JSONArray getArrayDocumentDigest(String hashes, String description){
		String label;
		if(description == null) label = "Document to Sign";
		else label = description;

		String[] hashArray = hashes.split(",");
		JSONArray documentDigests = new JSONArray();
		for(String hash: hashArray){
			JSONObject documentDigestObj = new JSONObject();
			documentDigestObj.put("hash", hash);
			documentDigestObj.put("label", label);
			documentDigests.put(documentDigestObj);
		}
		return documentDigests;
	}

	private JSONArray getTransactionDataFromAuthorizationDetails(String authorizationDetails){
		String authDetailsAuthorization = URLDecoder.decode(authorizationDetails, StandardCharsets.UTF_8);
		JSONArray authorizationDetailsArray = new JSONArray(authDetailsAuthorization);
		JSONObject authorizationDetailsJSON = authorizationDetailsArray.getJSONObject(0);
		String credentialID = authorizationDetailsJSON.getString("credentialID");
		String signatureQualifier = authorizationDetailsJSON.getString("signatureQualifier");
		String hashAlgorithmOID = authorizationDetailsJSON.getString("hashAlgorithmOID");
		JSONArray documentDigests = authorizationDetailsJSON.getJSONArray("documentDigests");
		JSONArray locations = authorizationDetailsJSON.getJSONArray("locations");
		return getTransactionData(credentialID, hashAlgorithmOID, documentDigests);
	}

	private JSONArray getTransactionData(String credentialID, String hashAlgorithmOID, JSONArray documentDigestsRequested){
		JSONArray transaction_data = new JSONArray();

		JSONObject transaction_data_object = new JSONObject();
		transaction_data_object.put("type", "qes_authorization");

		List<String> credentials_ids = new ArrayList<>();
		credentials_ids.add(PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID);
		transaction_data_object.put("credential_ids", credentials_ids);

		transaction_data_object.put("credentialID", credentialID);

		JSONArray documentDigests = new JSONArray();
		for(int i = 0; i < documentDigestsRequested.length(); i++){
			JSONObject jsonObject = documentDigestsRequested.getJSONObject(i);
			JSONObject documentDigestSingle = new JSONObject();
			documentDigestSingle.put("label", jsonObject.get("label"));
			documentDigestSingle.put("DTBS/R", jsonObject.get("hash"));
			documentDigestSingle.put("DTBS/RHashAlgorithmOID", hashAlgorithmOID);
			documentDigests.put(documentDigestSingle);
		}
		transaction_data_object.put("documentDigests", documentDigests);
		transaction_data.put(transaction_data_object);
		return transaction_data;
	}










	// {"transaction_data":[
	// 	{
	// 		"documentDigests":[
	// 			{"label":"Document to Sign","DTBS/RHashAlgorithmOID":"2.16.840.1.101.3.4.2.1", "DTBS/R":"TDTxQVz2SXyKTE4plOqz+M4fvgD4xV0hwOiUPaNrX3c="}
	// 		],
	// 		"credential_ids":["eu.europa.ec.eudi.pid.1"],
	// 		"credentialID":"235ccc94-c11e-43ab-b238-b3d1fa9c8c49",
	// 		"type":"qes_authorization"
	// 	}
	// ]
	public void validateTransactionData(String verifier_message, URI url) throws OID4VPException {
		JSONObject vpToken;
		try{
			vpToken =  new JSONObject(verifier_message);
		}
		catch (JSONException e){
			logger.error("The message from Verifier is not a well formatted JSON. {}", e.getMessage());
			throw new OID4VPException(OID4VPEnumError.RESPONSE_VERIFIER_WITH_INVALID_FORMAT, "The message from Verifier is not a valid JSON.");
		}
		logger.info("Loaded verifier's message into JSON Object.");

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(url);

		if(!authorizeRequest.getScope().equals("credential")) return;
		if(!vpToken.has("transaction_data")) throw new OID4VPException(FAILED_TO_VALIDATE_TRANSACTION_DATA, "The transaction_data is missing from the OID4VP Verifier's response.");

		JSONArray transactionData = vpToken.getJSONArray("transaction_data");

		JSONArray documentDigests = getArrayDocumentDigest(authorizeRequest.getHashes(), authorizeRequest.getDescription());

		if(!validateTransactionData(transactionData, authorizeRequest.getCredentialID(), authorizeRequest.getHashAlgorithmOID(),documentDigests))
			throw new OID4VPException(FAILED_TO_VALIDATE_TRANSACTION_DATA, "Validation of the values of 'transaction_data' failed.");

	}

	public boolean validateTransactionData (
		  JSONArray transactionData,
		  String credentialID, String hashAlgorithmOID, JSONArray documentDigestsRequested
	){
		for (int i = 0; i < transactionData.length(); i++){
			JSONObject singleTransactionData = transactionData.getJSONObject(i);

			List<String> credentials_ids = (List<String>) singleTransactionData.get("credential_ids");
			if(!credentials_ids.contains(PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID)) return false;

			String type = singleTransactionData.getString("type");
			if(!type.equals("qes_authorization")) return false;


			Set<String> set1 = new HashSet<>();
			Set<String> set2 = new HashSet<>();

			JSONArray documentDigests = singleTransactionData.getJSONArray("documentDigests");
			for(int j = 0; j < documentDigests.length(); j++){
				JSONObject singleDocumentDigestTD = documentDigests.getJSONObject(j);
				set1.add(singleDocumentDigestTD.toString());
				JSONObject singleDocumentDigest = documentDigestsRequested.getJSONObject(j);
				set2.add(singleDocumentDigest.toString());

				String DTBSRHashAlgorithmOID = singleDocumentDigest.getString("DTBS/RHashAlgorithmOID");
				if(!DTBSRHashAlgorithmOID.equals(hashAlgorithmOID)) return false;
			}

			if(!set1.equals(set2)) return false;

			String credentialId = singleTransactionData.getString("credentialID");
			if(!credentialId.equals(credentialID)) return false;
		}

		return true;
	}
}
