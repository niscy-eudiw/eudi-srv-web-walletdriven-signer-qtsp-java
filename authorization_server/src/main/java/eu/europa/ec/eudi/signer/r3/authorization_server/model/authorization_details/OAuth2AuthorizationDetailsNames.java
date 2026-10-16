package eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details;

import java.util.List;

public final class OAuth2AuthorizationDetailsNames {

    private OAuth2AuthorizationDetailsNames() {
    }

    public static final String TYPE = "type";
    public static final String LOCATIONS = "locations";
    public static final List<String> TYPE_CREDENTIAL = List.of("credential", "https://cloudsignatureconsortium.org/2025/credential");
    public static final List<String> TYPE_CREDENTIAL_CREATION = List.of("credential-creation", "https://cloudsignatureconsortium.org/2025/credential-creation");
    public static final List<String> TYPE_CREDENTIAL_DELETE = List.of("credential-deletion", "https://cloudsignatureconsortium.org/2025/credential-deletion");
    public static final String CREDENTIAL_ID = "credentialID";
    public static final String SIGNATURE_QUALIFIER = "signatureQualifier";
    public static final String HASH_ALGORITHM_OID = "hashAlgorithmOID";
    public static final String DOCUMENT_DIGESTS = "documentDigests";
    public static final String HASH = "hash";
    public static final String NUM_SIGNATURES = "numSignatures";
    public static final String HASH_TYPE = "hashType";
    public static final String SIGNED_PROPS = "signed_props";
    public static final String CIRCUMSTANTIAL_DATA = "circumstantialData";
    public static final String ACR_VALUES = "acr_values";
    public static final String CREDENTIAL_CREATION_REQUEST = "credentialCreationRequest";
    public static final String CERTIFICATE_POLICY = "certificatePolicy";
    public static final String SUBJECT_DATA = "subjectData";
}
