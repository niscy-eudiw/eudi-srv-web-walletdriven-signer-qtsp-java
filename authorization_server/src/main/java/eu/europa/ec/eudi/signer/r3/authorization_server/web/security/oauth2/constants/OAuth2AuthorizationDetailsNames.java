package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants;

import java.util.List;

public final class OAuth2AuthorizationDetailsNames {

	private OAuth2AuthorizationDetailsNames() {}

	public static final String TYPE = "type";

	// Type values
	public static final List<String> TYPE_CREDENTIAL = List.of("credential", "https://cloudsignatureconsortium.org/2025/credential");
	public static final List<String> TYPE_CREDENTIAL_CREATION = List.of("credential_creation", "https://cloudsignatureconsortium.org/2025/credential-creation");
	public static final List<String> TYPE_CREDENTIAL_DELETE = List.of("credential_deletion", "https://cloudsignatureconsortium.org/2025/credential-deletion");

	// Fields credential scope
	public static final String CREDENTIAL_ID = "credentialID";
	public static final String SIGNATURE_QUALIFIER = "signatureQualifier";
	public static final String HASH_ALGORITHM_OID = "hashAlgorithmOID";
	public static final String DOCUMENT_DIGESTS = "documentDigests";
	public static final String HASH = "hash";

	// New fields for the updated credential scope (1.1.4)
	public static final String NUM_SIGNATURES = "numSignatures";
	public static final String HASH_TYPE = "hashType";
	public static final String SIGNED_PROPS = "signed_props";
	public static final String CIRCUMSTANTIAL_DATA = "circumstantialData";

	// New fields for credential-creation scope (1.1.2)
	public static final String ACR_VALUES = "acr_values";
	public static final String CREDENTIAL_CREATION_REQUEST = "credentialCreationRequest";
	public static final String CERTIFICATE_POLICY = "certificatePolicy";
	public static final String SUBJECT_DATA = "subjectData";
}
