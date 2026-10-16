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
import jakarta.validation.constraints.Pattern;

public class CredentialsListRequest {
    @Pattern(regexp = "^[A-Za-z0-9+/=]{43}=$", message = "Invalid parameter userID")
    @Schema(description = "Identifier of the user. Must not be sent: service authorization is user-specific and the "
            + "user is identified by the access token.")
    private String userID;
    @Schema(description = "Whether to return the information about each credential in `credentialInfos`.",
            defaultValue = "false")
    private Boolean credentialInfo = false;
    @Pattern(regexp = "^(none|single|chain)$", message = "Invalid parameter certificates")
    @Schema(description = "Certificates to return in `credentialInfos`: none, only the end entity certificate, or "
            + "the full certificate chain. Only used if `credentialInfo` is `true`.",
            allowableValues = {"none", "single", "chain"}, defaultValue = "single")
    private String certificates = "single";
    @Schema(description = "Whether to return the information from the end entity certificate. "
            + "Only used if `credentialInfo` is `true`.", defaultValue = "false")
    private Boolean certInfo = false;
    @Schema(description = "Whether to return the authorization mode of each credential in `credentialInfos`. Only "
            + "used if `credentialInfo` is `true`.", defaultValue = "false")
    private Boolean authInfo = false;
    @Schema(description = "Whether to return only the valid credentials. Ignored if the remote service does not "
            + "support it: the `onlyValid` output parameter indicates whether the filter was applied.",
            defaultValue = "false")
    private Boolean onlyValid = false;

    @Pattern(regexp = "^[a-zA-Z]{2}(-[a-zA-Z]{2})?$", message = "Invalid language code")
    @Schema(description = "Preferred language of the response (RFC 5646).", example = "en-US")
    private String lang;
    @Schema(description = "Arbitrary data from the signature application.")
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