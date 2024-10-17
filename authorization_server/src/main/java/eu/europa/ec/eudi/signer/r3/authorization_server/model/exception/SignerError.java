package eu.europa.ec.eudi.signer.r3.authorization_server.model.exception;

public enum SignerError {
    UnexpectedError("unexpected_error", "Unexpected Error", 500),

    FailedConnectionToVerifier("failed_connection_to_verifier",
          "An error occurred when trying to connect to the Verifier", 404), // 404 not found

    MissingDataInResponseVerifier("missing_data_in_response_verifier",
          "The response received from the verifier is missing required information.", 500),

    // Errors while validating the VP Token:
    FailedToValidateVPToken("failed_validate_vp_token", "The validation step of the VP Token failed.", 500), // 500

    PresentationSubmissionMissingData("presentation_submission_missing_data",
          "The validation of the VP Token failed, because the validation of presentation submission failed.",
          432),

    StatusVPTokenInvalid("status_vptoken_invalid", "The status present in the VP Token is invalid.", 433),

    CertificateIssuerAuthInvalid("certificate_issuerauth_invalid",
          "The certificate present in the IssuerAuth in the VP Token is invalid.", 434),

    SignatureIssuerAuthInvalid("signature_issuerauth_invalid",
          "The signature present in the IssuerAuth in the VP Token is invalid.", 435),

    DocTypeMSODifferentFromDocuments("doctype_mso_different_from_documents",
          "The DocType in the MSO is different from the DocType in the document of the VPToken", 436),

    IntegrityVPTokenNotVerified("integrity_vptoken_not_verified",
          "The digest of the IssuerSignedItem are not equal to the digests in MSO. Couldn't verify the integrity.",
          437),

    ValidityInfoInvalid("validity_info_vptoken_invalid", "The ValidityInfo from the VPToken was not valid.", 438),

    UserNotOver18("user_not_over_18", "User must be over 18.", 439),

    VPTokenMissingValues("vptoken_missing_requested_values", "The VPToken is missing values requested.", 440);

    private final String code;
    private final int httpCode;
    private final String desc;

    SignerError(String code, String desc, int httpCode) {
        this.code = code;
        this.desc = desc;
        this.httpCode = httpCode;
    }

    public String getCode() {
        return code;
    }

    public int getHttpCode() {
        return httpCode;
    }

    public String getDescription() {
        return desc;
    }

    /**
     * Returns a formatted message that could be used to return an error message as
     * a response to the API requests.
     * The followed format would be, for example, [ user_not_found ] User not found
     *
     * @return a formatted message
     */
    public String getFormattedMessage() {
        return "[ " + this.code + " ] " + this.desc;
    }
}
