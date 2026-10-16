package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.AuthorizationDetailsParser;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.dto.AuthorizationDetails;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.dto.CredentialAuthorizationDetails;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.dto.DocumentDigest;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.dto.OAuth2AuthorizeRequest;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class TransactionDataService {

    private static final Logger logger = LoggerFactory.getLogger(TransactionDataService.class);

    public JSONArray getTransactionData(String oauth2AuthorizeRequestUrl) throws Exception {
        URI url = new URI(oauth2AuthorizeRequestUrl);
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(url);
        return getTransactionDataFromRequest(authorizeRequest);
    }

    public JSONArray getTransactionData(HttpServletRequest request) throws Exception {
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.from(request);
        return getTransactionDataFromRequest(authorizeRequest);
    }

    private JSONArray getTransactionDataFromRequest(OAuth2AuthorizeRequest authorizeRequest) throws Exception {
        logger.info("Creating TransactionData for Request: {}", authorizeRequest);
        JSONArray transactionData = null;
        if (authorizeRequest.getScope().equals("credential")) {
            if (authorizeRequest.getAuthorization_details() != null) {
                transactionData = getTransactionDataFromAuthorizationDetails(authorizeRequest.getAuthorization_details());
            } else {
                transactionData = getTransactionDataFromRequestParams(authorizeRequest);
            }
        }
        logger.info("Transaction_Data: {}", transactionData);
        return transactionData;
    }

    private JSONArray getTransactionDataFromAuthorizationDetails(String authorizationDetails) throws Exception {
        List<AuthorizationDetails> authorizationDetailsObject = AuthorizationDetailsParser.parse(authorizationDetails);

        JSONArray transactionData = new JSONArray();
        for (AuthorizationDetails a : authorizationDetailsObject) {
            QesApprovalRequest qar = new QesApprovalRequest((CredentialAuthorizationDetails) a);
            for (DocumentDigest di : qar.signatureCreationApproval.documentDigests) {
                di.setHashType("dtbsr");
            }
            JSONObject qesApprovalRequest = qar.toJSONObject();
            transactionData.put(qesApprovalRequest);
        }
        return transactionData;
    }

    private JSONArray getTransactionDataFromRequestParams(OAuth2AuthorizeRequest authorizeRequest) throws Exception {
        String credentialId = authorizeRequest.getCredentialID();
        String signatureQualifier = authorizeRequest.getSignatureQualifier();
        int numSignatures = Integer.parseInt(authorizeRequest.getNumSignatures());
        String hashes = authorizeRequest.getHashes();
        String description = authorizeRequest.getDescription();
        String hashAlgorithmOID = authorizeRequest.getHashAlgorithmOID();
        JSONObject qar = new QesApprovalRequest(credentialId, signatureQualifier, numSignatures, hashes, description, hashAlgorithmOID).toJSONObject();
        return new JSONArray().put(qar);
    }

    static class QesApprovalRequest {

        private final String type;
        private final List<String> credentialIds;
        private final List<String> locations;
        private final SignatureCreationApproval signatureCreationApproval;

        public QesApprovalRequest(String credentialId, String signatureQualifier, int numSignatures, String hashes, String description, String hashAlgorithmOID) {
            this.type = "https://cloudsignatureconsortium.org/2025/qes-approval";
            this.credentialIds = new ArrayList<>();
            this.credentialIds.add("query_0");
            this.locations = new ArrayList<>();
            this.signatureCreationApproval = new SignatureCreationApproval(credentialId, signatureQualifier, numSignatures, hashes, description, hashAlgorithmOID);
        }

        public QesApprovalRequest(CredentialAuthorizationDetails authorizationDetails) {
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

        public JSONObject toJSONObject() throws Exception {
            JSONObject transactionDataObject = new JSONObject();
            transactionDataObject.put("type", this.type);
            transactionDataObject.put("credential_ids", this.credentialIds);
            this.signatureCreationApproval.addToJSONObject(transactionDataObject);
            return transactionDataObject;
        }
    }

    static class SignatureCreationApproval {

        private final String credentialId;
        private final String signatureQualifier;
        private final int numSignatures;
        private final List<DocumentDigest> documentDigests;
        private final String hashAlgorithmOID;

        public SignatureCreationApproval(String credentialId, String signatureQualifier, int numSignatures, String hashes, String description, String hashAlgorithmOID) {
            this.credentialId = credentialId;
            this.signatureQualifier = signatureQualifier;
            this.numSignatures = numSignatures;
            String[] hashesList = hashes.split(",");
            this.documentDigests = new ArrayList<>();
            for (String h : hashesList) {
                documentDigests.add(new DocumentDigest(description, h));
            }
            this.hashAlgorithmOID = hashAlgorithmOID;
        }

        public SignatureCreationApproval(String credentialId, String signatureQualifier, String numSignatures, List<DocumentDigest> hashes, String hashAlgorithmOID) {
            this.credentialId = credentialId;
            this.signatureQualifier = signatureQualifier;
            this.numSignatures = Integer.parseInt(numSignatures);
            this.documentDigests = hashes;
            this.hashAlgorithmOID = hashAlgorithmOID;
        }

        public void addToJSONObject(JSONObject transactionDataObject) throws Exception {
            transactionDataObject.put("credentialID", this.credentialId);
            transactionDataObject.put("signatureQualifier", this.signatureQualifier);
            transactionDataObject.put("numSignatures", this.numSignatures);
            JSONArray documentDigests = new JSONArray();
            for (DocumentDigest d : this.documentDigests) {
                documentDigests.put(d.toJSON());
            }
            transactionDataObject.put("documentDigests", documentDigests);
            transactionDataObject.put("hashAlgorithmOID", this.hashAlgorithmOID);
        }
    }
}
