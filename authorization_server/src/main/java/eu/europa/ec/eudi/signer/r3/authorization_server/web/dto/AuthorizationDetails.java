package eu.europa.ec.eudi.signer.r3.authorization_server.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2AuthorizationDetailsNames;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthorizationDetails{

	@JsonProperty(OAuth2AuthorizationDetailsNames.TYPE)
	private String type;

	@JsonProperty(OAuth2AuthorizationDetailsNames.ACR_VALUES)
	private List<String> acrValues;

	@JsonProperty(OAuth2AuthorizationDetailsNames.CREDENTIAL_CREATION_REQUEST)
	private CredentialCreationRequest credentialCreationRequest;

	@JsonProperty("locations")
	private List<String> locations;

	@JsonProperty(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID)
	private String credentialId;

	@JsonProperty(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER)
	private String signatureQualifier;

	@JsonProperty(OAuth2AuthorizationDetailsNames.NUM_SIGNATURES)
	private String numSignatures;

	@JsonProperty(OAuth2AuthorizationDetailsNames.DOCUMENT_DIGESTS)
	private List<DocumentInfo> documentDigests;

	@JsonProperty(OAuth2AuthorizationDetailsNames.HASH_ALGORITHM_OID)
	private String hashAlgorithmOid;

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public List<String> getAcrValues() {
		return acrValues;
	}

	public void setAcrValues(List<String> acrValues) {
		this.acrValues = acrValues;
	}

	public CredentialCreationRequest getCredentialCreationRequest() {
		return credentialCreationRequest;
	}

	public void setCredentialCreationRequest(CredentialCreationRequest credentialCreationRequest) {
		this.credentialCreationRequest = credentialCreationRequest;
	}

	public List<String> getLocations() {
		return locations;
	}

	public void setLocations(List<String> locations) {
		this.locations = locations;
	}

	public String getCredentialId() {
		return credentialId;
	}

	public void setCredentialId(String credentialId) {
		this.credentialId = credentialId;
	}

	public String getSignatureQualifier() {
		return signatureQualifier;
	}

	public void setSignatureQualifier(String signatureQualifier) {
		this.signatureQualifier = signatureQualifier;
	}

	public String getNumSignatures() {
		return numSignatures;
	}

	public void setNumSignatures(String numSignatures) {
		this.numSignatures = numSignatures;
	}

	public List<DocumentInfo> getDocumentDigests() {
		return documentDigests;
	}

	public void setDocumentDigests(List<DocumentInfo> documentDigests) {
		this.documentDigests = documentDigests;
	}

	public String getHashAlgorithmOid() {
		return hashAlgorithmOid;
	}

	public void setHashAlgorithmOid(String hashAlgorithmOid) {
		this.hashAlgorithmOid = hashAlgorithmOid;
	}

	@Override
	public String toString() {
		return "AuthorizationDetails{" +
			  "type='" + type + '\'' +
			  ", acrValues=" + acrValues +
			  ", credentialCreationRequest=" + credentialCreationRequest +
			  ", locations=" + locations +
			  ", credentialId='" + credentialId + '\'' +
			  ", signatureQualifier='" + signatureQualifier + '\'' +
			  ", numSignatures='" + numSignatures + '\'' +
			  ", documentDigests=" + documentDigests +
			  ", hashAlgorithmOid='" + hashAlgorithmOid + '\'' +
			  '}';
	}
}