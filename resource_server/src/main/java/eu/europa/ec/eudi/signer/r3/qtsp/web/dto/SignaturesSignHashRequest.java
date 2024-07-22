package eu.europa.ec.eudi.signer.r3.qtsp.web.dto;

import java.util.List;

import jakarta.validation.constraints.NotBlank;

public class SignaturesSignHashRequest {
    @NotBlank
    private String credentialID;
    // the signature activation data returned by the Credential Authorization methods
    private String SAD;
    @NotBlank
    // one or more hash values to be signed. This parameter SHALL contain the Base64-encoded raw message digests
    private List<String> hashes;
    // the OID of the algorithm used to calculate the hash value.
    private String hashAlgorithmOID;
    @NotBlank
    // the OID of the algorithm to use for signing
    private String signAlgo;
    // the Base64-encoded DER-encoded ASN.1 signature parameters, if required by the signature algorithm
    private String signAlgoParams;
    // A or S
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
