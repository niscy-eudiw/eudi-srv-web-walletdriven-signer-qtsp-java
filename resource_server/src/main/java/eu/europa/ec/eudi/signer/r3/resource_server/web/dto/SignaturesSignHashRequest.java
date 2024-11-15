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

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;

public class SignaturesSignHashRequest {
    @NotBlank(message = "Missing (or invalid type) string parameter credentialID")
    @Pattern(regexp = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
          message = "Invalid parameter credentialID")
    private String credentialID;

    // the signature activation data returned by the Credential Authorization methods
    private String SAD;

    // one or more hash values to be signed. This parameter SHALL contain the Base64-encoded raw message digests
    @NotEmpty(message = "Empty hash array")
    //@NotBlank(message = "Missing (or invalid type) array parameter hash")
    private List<@Pattern(regexp = "([a-zA-Z0-9]|%[0-9A-Fa-f]{2}|[-_.=])+", message = "Each hash must be URL-encoded") String> hashes;

    // the OID of the algorithm used to calculate the hash value.
    @Pattern(regexp = "^\\d+\\.\\d+\\.\\d+(\\.\\d+)+$", message = "Invalid parameter hashAlgorithmOID")
    private String hashAlgorithmOID;

    // the OID of the algorithm to use for signing
    @NotBlank
    @Pattern(regexp = "^\\d+\\.\\d+\\.\\d+(\\.\\d+)+$", message = "Sign algorithm OID must be in numeric OID format")
    private String signAlgo;

    // the Base64-encoded DER-encoded ASN.1 signature parameters, if required by the signature algorithm
    private String signAlgoParams;

    // A or S
    @Pattern(regexp = "^[AS]$", message = "Operation mode must be either 'A' or 'S'")
    private String operationMode;
    private int validity_period;
    private String response_uri;
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
