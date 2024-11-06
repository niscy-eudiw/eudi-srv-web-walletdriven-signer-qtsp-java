package eu.europa.ec.eudi.signer.r3.resource_server.web.dto;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoAuth;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoCert;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoKey;

import jakarta.validation.constraints.NotBlank;

public class CredentialsListResponse {
    @NotBlank
    private List<String> credentialIDs;

    private List<CredentialInfo> credentialInfos;

    private Boolean onlyValid;

    public CredentialsListResponse(){
        this.credentialIDs = new ArrayList<>();
        this.credentialInfos = new ArrayList<>();
        this.onlyValid = false;
    }

    public CredentialsListResponse(List<String> credentialIDs, List<CredentialInfo> credentialInfos, Boolean onlyValid){
        this.credentialIDs = credentialIDs;
        this.credentialInfos = credentialInfos;
        this.onlyValid = onlyValid;
    }

    public List<String> getCredentialIDs() {
        return credentialIDs;
    }

    public void setCredentialIDs(List<String> credentialIDs) {
        this.credentialIDs = credentialIDs;
    }

    public List<CredentialInfo> getCredentialInfos() {
        return credentialInfos;
    }

    public void setCredentialInfos(List<CredentialInfo> credentialInfos) {
        this.credentialInfos = credentialInfos;
    }

    public Boolean getOnlyValid() {
        return onlyValid;
    }

    public void setOnlyValid(Boolean onlyValid) {
        this.onlyValid = onlyValid;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "CredentialsListResponse{" +
                "credentialIDs=" + credentialIDs +
                ", credentialInfos=" + credentialInfos +
                ", onlyValid=" + onlyValid +
                '}';
    }

    public static class CredentialInfo {
        @NotBlank
        private String credentialID;
        private String description;
        private String signatureQualifier;
        private CredentialsInfoKey key;
        private CredentialsInfoCert cert;
        private CredentialsInfoAuth auth;

        private String SCAL = "1"; // 1 | 2
        // >= 1
        @NotBlank
        private int multisign;
        private String lang;

        public @NotBlank String getCredentialID() {
            return credentialID;
        }

        public void setCredentialID(@NotBlank String credentialID) {
            this.credentialID = credentialID;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getSignatureQualifier() {
            return signatureQualifier;
        }

        public void setSignatureQualifier(String signatureQualifier) {
            this.signatureQualifier = signatureQualifier;
        }

        public CredentialsInfoKey getKey() {
            return key;
        }

        public void setKey(CredentialsInfoKey key) {
            this.key = key;
        }

        public CredentialsInfoCert getCert() {
            return cert;
        }

        public void setCert(CredentialsInfoCert cert) {
            this.cert = cert;
        }

        public CredentialsInfoAuth getAuth() {
            return auth;
        }

        public void setAuth(CredentialsInfoAuth auth) {
            this.auth = auth;
        }

        @JsonProperty("SCAL")
        public String getSCAL() {
            return SCAL;
        }

        public void setSCAL(String SCAL) {
            this.SCAL = SCAL;
        }

         public int getMultisign() {
            return multisign;
        }

        public void setMultisign(int multisign) {
            this.multisign = multisign;
        }

        public String getLang() {
            return lang;
        }

        public void setLang(String lang) {
            this.lang = lang;
        }

        @Override
        public String toString() {
            return "CredentialInfo{" +
                    "credentialID='" + credentialID + '\'' +
                    ", description='" + description + '\'' +
                    ", signatureQualifier='" + signatureQualifier + '\'' +
                    ", key=" + key +
                    ", cert=" + cert +
                    ", auth=" + auth +
                    ", SCAL='" + SCAL + '\'' +
                    ", multisign=" + multisign +
                    ", lang='" + lang + '\'' +
                    '}';
        }
    }
}
