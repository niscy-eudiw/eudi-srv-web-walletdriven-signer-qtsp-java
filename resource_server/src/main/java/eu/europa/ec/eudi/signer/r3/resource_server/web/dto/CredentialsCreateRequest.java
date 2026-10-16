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

package eu.europa.ec.eudi.signer.r3.resource_server.web.dto;

import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.json.JSONObject;

import java.util.List;

public class CredentialsCreateRequest {

    /**
     * credentialCreationRequest object as defined in CSC DM.
     * certificatePolicy is Required Conditional, subjectData is Optional.
     */
    @NotNull(message = "Missing required parameter credentialCreationRequest")
    @Valid
    @Schema(description = "Parameters of the credential to create.")
    private CredentialCreationRequest credentialCreationRequest;

    @Schema(description = "Whether to return the information about the new credential.", defaultValue = "false")
    private boolean credentialInfo;

    @Schema(description = "Certificates to return: none, only the end entity certificate, or the full certificate "
            + "chain. Only used if `credentialInfo` is `true`.", allowableValues = {"none", "single", "chain"})
    private String certificates;

    @Schema(description = "Whether to return the information from the end entity certificate. Only used if "
            + "`credentialInfo` is `true`.", defaultValue = "false")
    private boolean certInfo;

    @ArraySchema(arraySchema = @Schema(description = "Authentication data objects."),
            schema = @Schema(type = "object"))
    private List<JSONObject> authData;


    @Schema(name = "CredentialCreationRequest")
    public static class CredentialCreationRequest {
        // Required Conditional per CSC DM — may be empty string if not needed
        @Schema(description = "Certificate policy in accordance with which the certificate is issued. Not supported: "
                + "ignored.")
        private String certificatePolicy;

        // Optional — subject data to include in the certificate (name, country, etc.)
        @Schema(description = "Subject data to include in the certificate. If absent, it is taken from the identity "
                + "claims of the access token.")
        private SubjectData subjectData;

        public String getCertificatePolicy() { return certificatePolicy; }
        public void setCertificatePolicy(String certificatePolicy) { this.certificatePolicy = certificatePolicy; }

        public SubjectData getSubjectData() { return subjectData; }
        public void setSubjectData(SubjectData subjectData) { this.subjectData = subjectData; }
    }

    @Schema(name = "SubjectData")
    public static class SubjectData {
        @Schema(description = "Given name of the subject.", example = "Jane")
        private String givenName;
        @Schema(description = "Surname of the subject.", example = "Doe")
        private String surname;
        @Schema(description = "ISO 3166-1 Alpha-2 code of the country that issued the subject's identity.",
                example = "PT")
        private String issuingCountry;

        public String getGivenName() { return givenName; }
        public void setGivenName(String givenName) { this.givenName = givenName; }
        public String getSurname() { return surname; }
        public void setSurname(String surname) { this.surname = surname; }
        public String getIssuingCountry() { return issuingCountry; }
        public void setIssuingCountry(String issuingCountry) { this.issuingCountry = issuingCountry; }
    }

    public CredentialCreationRequest getCredentialCreationRequest() { return credentialCreationRequest; }

    public void setCredentialCreationRequest(CredentialCreationRequest credentialCreationRequest) {
        this.credentialCreationRequest = credentialCreationRequest;
    }

    public boolean getCredentialInfo() {
        return credentialInfo;
    }

    public void setCredentialInfo(boolean credentialInfo) {
        this.credentialInfo = credentialInfo;
    }

    public String getCertificates() {
        return certificates;
    }

    public void setCertificates(String certificates) {
        this.certificates = certificates;
    }

    public boolean getCertInfo() {
        return certInfo;
    }

    public void setCertInfo(boolean certInfo) {
        this.certInfo = certInfo;
    }

    public List<JSONObject> getAuthData() {
        return authData;
    }

    public void setAuthData(List<JSONObject> authData) {
        this.authData = authData;
    }

    @Override
    public String toString() {
        return "CredentialsCreateRequest{credentialCreationRequest=" + credentialCreationRequest + "'}";
    }
}
