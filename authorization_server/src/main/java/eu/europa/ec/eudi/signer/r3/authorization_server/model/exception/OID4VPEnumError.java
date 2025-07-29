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
    UNEXPECTED_ERROR("unexpected_error",
          "Something went wrong on our end during sign-in. Please try again in a few moments.", 500),

    // message to the user from the description
    FAILED_CONNECTION_TO_VERIFIER("failed_connection_to_verifier",
          "Unable to reach the authentication service. Please try again or contact support if the issue persists.", 404), // 404 not found

    // message to the user from the description
    MISSING_DATA_IN_RESPONSE_VERIFIER("missing_data_in_response_verifier",
          "The authentication service response is incomplete. Please try again or contact support if the issue persists.", 500),

    // message to the user from the description
    RESPONSE_VERIFIER_WITH_INVALID_FORMAT("response_verifier_with_invalid_format",
          "We encountered an issue with the response from the authentication service. Please try again or reach out to support if the issue persists.", 500),

    // message from the OID4VPException Message
    VP_TOKEN_MISSING_VALUES("vptoken_missing_required_values",
          "The VPToken is missing values required.", 440),

    // message to the user from the description
    PRESENTATION_SUBMISSION_MISSING_DATA("presentation_submission_missing_data",
          OID4VPEnumError.general_message,
          "Additional Information For Developers: Validation of the VP Token failed: the presentation_submission is invalid.",
          432),

    // message to the user from the description
    STATUS_VP_TOKEN_INVALID("status_vptoken_invalid",
          OID4VPEnumError.general_message,
          "Additional Information For Developers: Validation of the VP Token failed: The status present in the VP Token is invalid.",
          433),

    // message to the user from the description
    CERTIFICATE_ISSUER_AUTH_INVALID("certificate_issuerauth_invalid",
          OID4VPEnumError.general_message,
          "Additional Information For Developers: Validation of the VP Token failed: The validation of the certificate in the IssuerAuth of the VP Token is failed.",
          434),

    // message to the user from the description
    CONNECTION_VERIFIER_TIMED_OUT("connection_verifier_timed_out",
          "Unable to complete the authentication. The process of waiting the response from the authentication service timed-out. Please try again.",
          504), // 504 gateway timeout

    // Errors while validating the VP Token:
    FAILED_TO_VALIDATE_VP_TOKEN_THROUGH_VERIFIER("failed_validate_vp_token_through_verifier",
          "It was impossible to validate the VP Token using the OID4VP Verifier.", 500),

    FAILED_TO_VALIDATE_VP_TOKEN("failed_validate_vp_token", "The validation step of the VP Token failed.", 500), // 500

    SIGNATURE_ISSUER_AUTH_INVALID("signature_issuerauth_invalid",
          "The signature present in the IssuerAuth in the VP Token is invalid.", 435),

    DOC_TYPE_MSO_DIFFERENT_FROM_DOCUMENTS("doctype_mso_different_from_documents",
          "The DocType in the MSO is different from the DocType in the document of the VPToken", 436),

    INTEGRITY_VP_TOKEN_NOT_VERIFIED("integrity_vptoken_not_verified",
          "The digest of the IssuerSignedItem are not equal to the digests in MSO. Couldn't verify the integrity.",
          437),

    VALIDITY_INFO_INVALID("validity_info_vptoken_invalid", "The ValidityInfo from the VPToken was not valid.", 438);

    private final String code;
    private final int httpCode;
    private final String desc;
    private final String additionalInformation;
    private static final String general_message = "Unable to complete the authentication. Please try again or contact support if the issue persists.";

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
