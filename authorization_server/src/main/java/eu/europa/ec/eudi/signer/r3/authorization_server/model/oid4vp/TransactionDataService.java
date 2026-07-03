package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import com.fasterxml.jackson.core.JsonProcessingException;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.AuthorizationDetails;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.AuthorizationDetailsProcessing;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPException;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.DocumentInfo;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2AuthorizeRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONArray;
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

@Component
public class TransactionDataService {
	public static final String PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID = "eu.europa.ec.eudi.pid.1";
	private static final Logger logger = LoggerFactory.getLogger(TransactionDataService.class);

	public JSONArray getTransactionData(String oauth2AuthorizeRequestUrl) throws URISyntaxException, JsonProcessingException {
		URI url = new URI(oauth2AuthorizeRequestUrl);
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(url);
		return getTransactionDataFromRequest(authorizeRequest);
	}

	public JSONArray getTransactionData(HttpServletRequest request) throws JsonProcessingException {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(request);
		return getTransactionDataFromRequest(authorizeRequest);
	}

	private JSONArray getTransactionDataFromRequest(OAuth2AuthorizeRequest authorizeRequest) throws JsonProcessingException {
		logger.info("Creating TransactionData for Request: {}", authorizeRequest);
		JSONArray transactionData = null;
		if(authorizeRequest.getScope().equals("credential")){
			if(authorizeRequest.getAuthorization_details() != null){
				transactionData = getTransactionDataFromAuthorizationDetails(authorizeRequest.getAuthorization_details());
			}
			else{
				transactionData = getTransactionDataFromRequestParams(authorizeRequest);
			}
		}
		logger.info("Transaction_Data: {}", transactionData);
		return transactionData;
	}

	private JSONArray getTransactionDataFromAuthorizationDetails(String authorizationDetails) throws JsonProcessingException {
		String authDetailsAuthorization = URLDecoder.decode(authorizationDetails, StandardCharsets.UTF_8);

		List<AuthorizationDetails> authorizationDetailsObject= AuthorizationDetailsProcessing.parse(authDetailsAuthorization);

		JSONArray transactionData = new JSONArray();
		for (AuthorizationDetails a: authorizationDetailsObject){
			JSONObject qesApprovalRequest = new QesApprovalRequest(a).toJSONObject();
			transactionData.put(qesApprovalRequest);
		}
		return transactionData;
	}

	private JSONArray getTransactionDataFromRequestParams(OAuth2AuthorizeRequest authorizeRequest) throws JsonProcessingException {
		String credentialId = authorizeRequest.getCredentialID();
		String signatureQualifier = authorizeRequest.getSignatureQualifier();
		int numSignatures = Integer.parseInt(authorizeRequest.getNumSignatures());
		String hashes = authorizeRequest.getHashes();
		String description = authorizeRequest.getDescription();
		String hashAlgorithmOID = authorizeRequest.getHashAlgorithmOID();
		return new JSONArray(new QesApprovalRequest(credentialId, signatureQualifier, numSignatures, hashes, description, hashAlgorithmOID).toJSONObject());
	}

	static class QesApprovalRequest{
		private final String type;
		private final List<String> credentialIds;
		private final List<String> locations;
		private final SignatureCreationApproval signatureCreationApproval;

		public QesApprovalRequest(String credentialId, String signatureQualifier, int numSignatures, String hashes, String description, String hashAlgorithmOID){
			this.type = "https://cloudsignatureconsortium.org/2025/qes-approval";
			this.credentialIds = new ArrayList<>();
			this.credentialIds.add("query_0");
			this.locations = new ArrayList<>();
			this.signatureCreationApproval = new SignatureCreationApproval(credentialId, signatureQualifier, numSignatures, hashes, description, hashAlgorithmOID);
		}

		public QesApprovalRequest(AuthorizationDetails authorizationDetails){
			this.type = "https://cloudsignatureconsortium.org/2025/qes-approval";
			this.credentialIds = new ArrayList<>();
			this.credentialIds.add("query_0");
			this.locations = authorizationDetails.getLocations();
			this.signatureCreationApproval = new SignatureCreationApproval(
				  authorizationDetails.getCredentialId(),
				  authorizationDetails.getSignatureQualifier(),
				  authorizationDetails.getNumSignatures(),
				  authorizationDetails.getDocumentDigests(),
				  authorizationDetails.getHashAlgorithmOid()
			);
		}

		public JSONObject toJSONObject() throws JsonProcessingException {
			JSONObject transactionDataObject = new JSONObject();
			transactionDataObject.put("type", this.type);
			transactionDataObject.put("credential_ids", this.credentialIds);
			this.signatureCreationApproval.addToJSONObject(transactionDataObject);
			return transactionDataObject;
		}
	}

	static class SignatureCreationApproval{
		private final String credentialId;
		private final String signatureQualifier;
		private final int numSignatures;
		private final List<DocumentInfo> documentDigests;
		private final String hashAlgorithmOID;

		public SignatureCreationApproval(String credentialId, String signatureQualifier, int numSignatures, String hashes, String description, String hashAlgorithmOID){
			this.credentialId = credentialId;
			this.signatureQualifier = signatureQualifier;
			this.numSignatures = numSignatures;
			String[] hashesList = hashes.split(",");
			List<DocumentInfo> documentDigests = new ArrayList<>();
			for (String h: hashesList){
				documentDigests.add(new DocumentInfo(description, h));
			}
			this.documentDigests = documentDigests;
			this.hashAlgorithmOID = hashAlgorithmOID;
		}

		public SignatureCreationApproval(String credentialId, String signatureQualifier, String numSignatures, List<DocumentInfo> hashes, String hashAlgorithmOID){
			this.credentialId = credentialId;
			this.signatureQualifier = signatureQualifier;
			this.numSignatures = Integer.parseInt(numSignatures);
			this.documentDigests = hashes;
			this.hashAlgorithmOID = hashAlgorithmOID;
		}

		public void addToJSONObject(JSONObject transactionDataObject) throws JsonProcessingException {
			transactionDataObject.put("credentialID", this.credentialId);
			transactionDataObject.put("signatureQualifier", this.signatureQualifier);
			transactionDataObject.put("numSignatures", this.numSignatures);
			JSONArray documentDigests = new JSONArray();
			for (DocumentInfo d: this.documentDigests){
				documentDigests.put(d.toJSON());
			}
			transactionDataObject.put("documentDigests", documentDigests);
			transactionDataObject.put("hashAlgorithmOID", this.hashAlgorithmOID);
		}
	}


	public void validateTransactionData(JSONObject vpToken, URI url) throws OID4VPException{
		/*String DeviceResponse = vpToken.getJSONObject("vp_token").getJSONArray("query_0").getString(0);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(url);

		if(!authorizeRequest.getScope().equals("credential")) return;
		if(!vpToken.has("transaction_data")) throw new OID4VPException(FAILED_TO_VALIDATE_TRANSACTION_DATA, "The transaction_data is missing from the OID4VP Verifier's response.");

		JSONArray transactionData = vpToken.getJSONArray("transaction_data");

		JSONArray documentDigests = getArrayDocumentDigest(authorizeRequest.getHashes(), authorizeRequest.getDescription());

		if(!validateTransactionData(transactionData, authorizeRequest.getCredentialID(), authorizeRequest.getHashAlgorithmOID(),documentDigests))
			throw new OID4VPException(FAILED_TO_VALIDATE_TRANSACTION_DATA, "Validation of the values of 'transaction_data' failed.");
		*/
	}

	private boolean validateTransactionData (
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
