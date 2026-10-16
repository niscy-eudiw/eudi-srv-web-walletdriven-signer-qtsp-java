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

import java.util.List;

import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;

public class SignaturesSignHashRequest {
    @NotBlank(message = "Missing (or invalid type) string parameter credentialID")
    @Pattern(regexp = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", message = "Invalid parameter credentialID")
    @Schema(description = "The unique identifier of the credential to sign with.")
    private String credentialID;
    @Schema(description = "Signature Activation Data returned by the credential authorization methods. Not used: the "
            + "credential authorization is given by the access token with `credential` scope.")
    private String SAD;
    @NotEmpty(message = "Empty hash array")
    @ArraySchema(arraySchema = @Schema(description = "Base64-encoded raw message digests to sign."))
    private List<String> hashes;
    @Pattern(regexp = "^\\d+\\.\\d+\\.\\d+(\\.\\d+)*+$", message = "Invalid parameter hashAlgorithmOID")
    @Schema(description = "OID of the algorithm used to calculate the hashes. Required unless implied by `signAlgo` or `signAlgoParams`. Must be SHA-256 or stronger.")
    private String hashAlgorithmOID;
    @NotBlank
    @Pattern(regexp = "^\\d+\\.\\d+\\.\\d+(\\.\\d+)*+$", message = "Sign algorithm OID must be in numeric OID format")
    @Schema(description = "OID of the signature algorithm.")
    private String signAlgo;
    @Schema(description = "Base64-encoded DER-encoded ASN.1 signature parameters, if required by `signAlgo`.")
    private String signAlgoParams;
    @Pattern(regexp = "^[AS]$", message = "Operation mode must be either 'A' or 'S'")
    @Schema(description = "Synchronous (`S`) or asynchronous (`A`) operation mode.", allowableValues = {"S", "A"})
    private String operationMode;
    @Schema(description = "Validity period of the asynchronous response, in miliseconds.")
    private int validity_period;
    @Schema(description = "URI to notify when the asynchronous operation completes.")
    private String response_uri;
    @Schema(description = "Arbitrary data from the signature application.")
    private String clientData;

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getSAD() {
        return SAD;
    }

    public void setSAD(String SAD) {
        this.SAD = SAD;
    }

    public List<String> getHashes() {
        return hashes;
    }

    public void setHashes(List<String> hashes) {
        this.hashes = hashes;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public void setSignAlgo(String signAlgo) {
        this.signAlgo = signAlgo;
    }

    public String getSignAlgoParams() {
        return signAlgoParams;
    }

    public void setSignAlgoParams(String signAlgoParams) {
        this.signAlgoParams = signAlgoParams;
    }

    public String getOperationMode() {
        return operationMode;
    }

    public void setOperationMode(String operationMode) {
        this.operationMode = operationMode;
    }

    public int getValidity_period() {
        return validity_period;
    }

    public void setValidity_period(int validity_period) {
        this.validity_period = validity_period;
    }

    public String getResponse_uri() {
        return response_uri;
    }

    public void setResponse_uri(String response_uri) {
        this.response_uri = response_uri;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "SignaturesSignHashRequestDTO{" +
                "credentialID='" + credentialID + '\'' +
                ", SAD='" + SAD + '\'' +
                ", hashes=" + hashes +
                ", hashAlgorithmOID='" + hashAlgorithmOID + '\'' +
                ", signAlgo='" + signAlgo + '\'' +
                ", signAlgoParams='" + signAlgoParams + '\'' +
                ", operationMode='" + operationMode + '\'' +
                ", validity_period=" + validity_period +
                ", response_uri='" + response_uri + '\'' +
                ", client_Data='" + clientData + '\'' +
                '}';
    }
}
