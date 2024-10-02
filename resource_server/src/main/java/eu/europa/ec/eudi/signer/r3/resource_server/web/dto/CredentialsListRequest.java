package eu.europa.ec.eudi.signer.r3.resource_server.web.dto;

public class CredentialsListRequest {
    private String userID;
    private Boolean credentialInfo = false;
    // none | single | chain
    private String certificates = "single";
    private Boolean certInfo = false;
    private Boolean authInfo = false;
    private Boolean onlyValid = false;
    private String lang;
    private String clientData;

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public Boolean getCredentialInfo() {
        return credentialInfo;
    }

    public void setCredentialInfo(Boolean credentialInfo) {
        this.credentialInfo = credentialInfo;
    }

    public String getCertificates() {
        return certificates;
    }

    public void setCertificates(String certificates) {
        this.certificates = certificates;
    }

    public Boolean getCertInfo() {
        return certInfo;
    }

    public void setCertInfo(Boolean certInfo) {
        this.certInfo = certInfo;
    }

    public Boolean getAuthInfo() {
        return authInfo;
    }

    public void setAuthInfo(Boolean authInfo) {
        this.authInfo = authInfo;
    }

    public Boolean getOnlyValid() {
        return onlyValid;
    }

    public void setOnlyValid(Boolean onlyValid) {
        this.onlyValid = onlyValid;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "CredentialsListRequestDTO{" +
                "userID='" + userID + '\'' +
                ", credentialInfo=" + credentialInfo +
                ", certificates='" + certificates + '\'' +
                ", certInfo=" + certInfo +
                ", authInfo=" + authInfo +
                ", onlyValid=" + onlyValid +
                ", lang='" + lang + '\'' +
                ", clientData='" + clientData + '\'' +
                '}';
    }
}