/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.authorization_server.model.exception;

public enum OID4VPEnumError {
    // message to the user from the description
    UnexpectedError("unexpected_error",
          "Something went wrong on our end during sign-in. Please try again in a few moments.", 500),

    // message to the user from the description
    FailedConnectionToVerifier("failed_connection_to_verifier",
          "Unable to reach the authentication service. Please try again or contact support if the issue persists.", 404), // 404 not found

    // message to the user from the description
    MissingDataInResponseVerifier("missing_data_in_response_verifier",
          "The authentication service response is incomplete. Please try again or contact support if the issue persists.", 500),

    // message to the user from the description
    ResponseVerifierWithInvalidFormat("response_verifier_with_invalid_format",
          "We encountered an issue with the response from the authentication service. Please try again or reach out to support if the issue persists.", 500),

    // message to the user from the description
    UserNotOver18("user_not_over_18",
          "This service is only available to users 18 and older. Thank you for understanding.", 439),

    // message from the OID4VPException Message
    VPTokenMissingValues("vptoken_missing_required_values",
          "The VPToken is missing values required.", 440),

    // message to the user from the description
    PresentationSubmissionMissingData("presentation_submission_missing_data",
		  "Unable to complete the authentication. Please try again or contact support if the issue persists.",
          "Additional Information For Developers: Validation of the VP Token failed: the presentation_submission is invalid.",
          432),

    // message to the user from the description
    StatusVPTokenInvalid("status_vptoken_invalid",
		  "Unable to complete the authentication. Please try again or contact support if the issue persists.",
          "Additional Information For Developers: Validation of the VP Token failed: The status present in the VP Token is invalid.",
          433),

    // message to the user from the description
    CertificateIssuerAuthInvalid("certificate_issuerauth_invalid",
          "Unable to complete the authentication. Please try again or contact support if the issue persists.",
          "Additional Information For Developers: Validation of the VP Token failed: The validation of the certificate in the IssuerAuth of the VP Token is failed.",
          434),

    // message to the user from the description
    ConnectionVerifierTimedOut("connection_verifier_timed_out",
          "Unable to complete the authentication. The process of waiting the response from the authentication service timed-out. Please try again.",
          504), // 504 gateway timeout


    // Errors while validating the VP Token:
    FailedToValidateVPToken("failed_validate_vp_token", "The validation step of the VP Token failed.", 500), // 500

    SignatureIssuerAuthInvalid("signature_issuerauth_invalid",
          "The signature present in the IssuerAuth in the VP Token is invalid.", 435),

    DocTypeMSODifferentFromDocuments("doctype_mso_different_from_documents",
          "The DocType in the MSO is different from the DocType in the document of the VPToken", 436),

    IntegrityVPTokenNotVerified("integrity_vptoken_not_verified",
          "The digest of the IssuerSignedItem are not equal to the digests in MSO. Couldn't verify the integrity.",
          437),

    ValidityInfoInvalid("validity_info_vptoken_invalid", "The ValidityInfo from the VPToken was not valid.", 438);



    private final String code;
    private final int httpCode;
    private final String desc;
    private final String additionalInformation;

    OID4VPEnumError(String code, String desc, int httpCode) {
        this.code = code;
        this.desc = desc;
        this.additionalInformation = "";
        this.httpCode = httpCode;
    }

    OID4VPEnumError(String code, String desc, String additionalInformation, int httpCode) {
        this.code = code;
        this.desc = desc;
        this.additionalInformation = additionalInformation;
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
        return this.desc + this.additionalInformation;
    }

    public String getFormattedMessageWithoutAdditionalInformation() {
        return this.desc;
    }

    public String getAdditionalInformation() {
        return additionalInformation;
    }
}
