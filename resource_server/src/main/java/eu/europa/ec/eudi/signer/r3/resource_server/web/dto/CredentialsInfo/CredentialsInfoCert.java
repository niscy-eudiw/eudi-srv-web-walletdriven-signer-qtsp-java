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

package eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo;

import java.util.List;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Certificate of the credential. `issuerDN`, `serialNumber`, `subjectDN`, `validFrom`, "
        + "`validTo`, `qcStatements` and `policy` are only returned if `certInfo` is `true`.")
public class CredentialsInfoCert {
    @Schema(description = "Status of the end entity certificate.",
            allowableValues = {"valid", "expired", "revoked", "suspended"})
    private String status;
    @Schema(description = "Base64-encoded DER certificates: the end entity certificate (`single`), followed by the "
            + "rest of the chain (`chain`). Absent if `certificates` is `none`.")
    private List<String> certificates;
    @Schema(description = "Issuer distinguished name of the end entity certificate.")
    private String issuerDN;
    @Schema(description = "Serial number of the end entity certificate, in decimal.")
    private String serialNumber;
    @Schema(description = "Subject distinguished name of the end entity certificate.")
    private String subjectDN;
    @Schema(description = "Start of the validity period of the end entity certificate (ASN.1 GeneralizedTime).")
    private String validFrom;
    @Schema(description = "End of the validity period of the end entity certificate (ASN.1 GeneralizedTime).")
    private String validTo;
    @Schema(description = "OIDs of the QC statements of the end entity certificate. Empty if there are none.")
    private List<String> qcStatements;
    @Schema(description = "OIDs of the certificate policies of the end entity certificate.")
    private List<String> policy;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public List<String> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<String> certificates) {
        this.certificates = certificates;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(String validFrom) {
        this.validFrom = validFrom;
    }

    public String getValidTo() {
        return validTo;
    }

    public void setValidTo(String validTo) {
        this.validTo = validTo;
    }

    public List<String> getQcStatements() {
        return qcStatements;
    }

    public void setQcStatements(List<String> qcStatements) {
        this.qcStatements = qcStatements;
    }

    public List<String> getPolicy() {
        return policy;
    }

    public void setPolicy(List<String> policy) {
        this.policy = policy;
    }

    @Override
    public String toString() {
        return "CredentialsInfoCert{" +
                "status='" + status + '\'' +
                ", certificates=" + certificates +
                ", issuerDN='" + issuerDN + '\'' +
                ", serialNumber='" + serialNumber + '\'' +
                ", subjectDN='" + subjectDN + '\'' +
                ", validFrom='" + validFrom + '\'' +
                ", validTo='" + validTo + '\'' +
                ", qcStatements=" + qcStatements +
                ", policy=" + policy +
                '}';
    }
}
