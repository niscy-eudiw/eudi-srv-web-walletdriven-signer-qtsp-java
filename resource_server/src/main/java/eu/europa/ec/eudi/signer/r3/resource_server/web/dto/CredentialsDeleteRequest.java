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

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public class CredentialsDeleteRequest {

    @NotNull(message = "Missing required parameter credentialDeletionRequest")
    @Schema(description = "Parameters of the credential to delete.")
    private CredentialDeletionRequest credentialDeletionRequest;

    @Schema(name = "CredentialDeletionRequest")
    public static class CredentialDeletionRequest {

        @NotBlank(message = "Missing required parameter credentialID")
        @Pattern(regexp = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                message = "Invalid parameter credentialID")
        @Schema(description = "Identifier of the credential to delete. Must be the one authorized in the access token.")
        private String credentialID;

        @Schema(description = "Whether to also revoke the certificate of the credential.")
        private boolean revoke;

        @Schema(description = "Revocation reason code (RFC 5280, section 5.3.1).")
        private int revocationReason;

        public String getCredentialID() {
            return credentialID;
        }

        public void setCredentialID(String credentialID) {
            this.credentialID = credentialID;
        }

        public boolean isRevoke() {
            return revoke;
        }

        public void setRevoke(boolean revoke) {
            this.revoke = revoke;
        }

        public int getRevocationReason() {
            return revocationReason;
        }

        public void setRevocationReason(int revocationReason) {
            this.revocationReason = revocationReason;
        }
    }

    public CredentialDeletionRequest getCredentialDeletionRequest() {
        return credentialDeletionRequest;
    }

    public void setCredentialDeletionRequest(CredentialDeletionRequest credentialDeletionRequest) {
        this.credentialDeletionRequest = credentialDeletionRequest;
    }
}
