package eu.europa.ec.eudi.signer.r3.authorization_server.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2AuthorizationDetailsNames;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CredentialCreationRequest {
	@JsonProperty(OAuth2AuthorizationDetailsNames.CERTIFICATE_POLICY)
	private String certificatePolicy;

	@JsonProperty(OAuth2AuthorizationDetailsNames.SUBJECT_DATA)
	private String subjectData;

	public String getCertificatePolicy() {
		return certificatePolicy;
	}

	public void setCertificatePolicy(String certificatePolicy) {
		this.certificatePolicy = certificatePolicy;
	}

	public String getSubjectData() {
		return subjectData;
	}

	public void setSubjectData(String subjectData) {
		this.subjectData = subjectData;
	}
}
