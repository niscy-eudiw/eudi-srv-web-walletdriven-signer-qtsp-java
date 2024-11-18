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

import jakarta.validation.constraints.Pattern;

public class CredentialsListRequest {
    @Pattern(regexp = "^[A-Za-z0-9+/=]{43}=$", message = "Invalid parameter userID")
    private String userID;
    private Boolean credentialInfo = false;
    // none | single | chain
    @Pattern(regexp = "^(none|single|chain)$", message = "Invalid parameter certificates")
    private String certificates = "single";
    private Boolean certInfo = false;
    private Boolean authInfo = false;
    private Boolean onlyValid = false;

    @Pattern(regexp = "^[a-zA-Z]{2}(-[a-zA-Z]{2})?$", message = "Invalid language code")
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