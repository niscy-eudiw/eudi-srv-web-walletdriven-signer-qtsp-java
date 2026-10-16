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

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import eu.europa.ec.eudi.signer.r3.resource_server.config.InfoConfig;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class InfoResponse {
    @NotBlank
    @Schema(description = "Version of the CSC API specification implemented by the remote service.")
    private String specs = "2.2.0.0";
    @NotBlank
    @Schema(description = "Commercial name of the remote service.")
    private String name = "remote Qualifies Electronic Signature (rQES) QTSP";
    @NotBlank
    @Schema(description = "URI of the image file containing the logo of the remote service.")
    private String logo = "img";
    @NotBlank
    @Schema(description = "ISO 3166-1 Alpha-2 code of the country where the remote service provider is established.")
    private String region = "EU";
    @NotBlank
    @Schema(description = "Language used in the responses (RFC 5646).")
    private String lang = "en-US";
    @NotBlank
    @Schema(description = "Free form description of the remote service, in the `lang` language.")
    private String description = "test qtsp";
    @NotBlank
    @Schema(description = "Supported service authorization mechanisms.")
    private List<String> authType;
    @Schema(description = "OAuth 2.0 authorization servers that can be used with the remote service.")
    private List<InfoConfig.OAuth2Server> oauth2Servers;
    @Schema(description = "Base URI of the OAuth 2.0 authorization server used by the remote service.")
    private String oauth2;
    @Schema(description = "Issuer identifier of the OAuth 2.0 authorization server (RFC 8414).")
    private String oauth2Issuer;
    @Schema(description = "Whether the authorization server supports Rich Authorization Requests (RFC 9396), i.e. `authorization_details`.")
    private Boolean supportsRar;
    @Schema(description = "Supported types of hashes to sign.")
    private List<String> supportedHashTypes;
    @Schema(description = "Whether the remote service supports the asynchronous operation mode (`A`).")
    private boolean asynchronousOperationMode;
    @NotBlank
    @Schema(description = "API methods implemented by the remote service.")
    private List<String> methods;
    @Schema(description = "Whether the remote service returns validation information.")
    private boolean validationInfo;
    @NotBlank
    @Schema(description = "Signature algorithms supported by the remote service.")
    private InfoConfig.SignAlgorithms signAlgorithms;
    @Schema(description = "Supported document types.")
    private List<String> documentTypes;
    @NotBlank
    @Schema(description = "Signature formats supported by the remote service.")
    private SignatureFormats signature_formats;
    @NotBlank
    @Schema(description = "Supported AdES conformance levels.")
    private List<String> conformance_levels;

    @Schema(name = "SignatureFormats")
    private static class SignatureFormats {
        @Schema(description = "Supported signature formats: `C` (CAdES), `X` (XAdES), `J` (JAdES), `P` (PAdES).")
        private List<String> formats;
        @Schema(description = "Supported signed envelope properties for each format, in the same order as `formats`.")
        private List<List<String>> envelope_properties;

        public SignatureFormats() {
            this.formats = new ArrayList<>();
            this.envelope_properties = new ArrayList<>();
        }

        public SignatureFormats(List<String> formats, List<List<String>> envelope_properties) {
            this.formats = formats;
            this.envelope_properties = envelope_properties;
        }

        public List<String> getFormats() {
            return formats;
        }

        public void setFormats(List<String> formats) {
            this.formats = formats;
        }

        public List<List<String>> getEnvelope_properties() {
            return envelope_properties;
        }

        public void setEnvelope_properties(List<List<String>> envelope_properties) {
            this.envelope_properties = envelope_properties;
        }
    }

    public InfoResponse() {
        this.authType = new ArrayList<>();
        this.methods = new ArrayList<>();
        this.signAlgorithms = new InfoConfig.SignAlgorithms();
        this.signature_formats = new SignatureFormats();
        this.conformance_levels = new ArrayList<>();
    }

    public InfoResponse(String specs, String name, String logo, String region, String lang, String description,
            List<String> authType, String oauth2, boolean asynchronousOperationMode, List<String> methods,
            boolean validationInfo, InfoConfig.SignAlgorithms signAlgorithms, List<String> signature_formats_formats,
            List<List<String>> signature_formats_envelope_properties, List<String> conformance_levels) {
        this.specs = specs;
        this.name = name;
        this.logo = logo;
        this.region = region;
        this.lang = lang;
        this.description = description;
        this.authType = authType;
        this.oauth2 = oauth2;
        this.asynchronousOperationMode = asynchronousOperationMode;
        this.methods = methods;
        this.validationInfo = validationInfo;
        this.signAlgorithms = signAlgorithms;
        this.signature_formats = new SignatureFormats(signature_formats_formats, signature_formats_envelope_properties);
        this.conformance_levels = conformance_levels;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "InfoResponse{" +
                "specs='" + specs + '\'' +
                ", name='" + name + '\'' +
                ", logo='" + logo + '\'' +
                ", region='" + region + '\'' +
                ", lang='" + lang + '\'' +
                ", description='" + description + '\'' +
                ", authType=" + authType +
                ", oauth2='" + oauth2 + '\'' +
                ", oauth2Issuer='" + oauth2Issuer + '\'' +
                ", asynchronousOperationMode=" + asynchronousOperationMode +
                ", methods=" + methods +
                ", validationInfo=" + validationInfo +
                ", signAlgorithms=" + signAlgorithms +
                ", signature_formats=" + signature_formats +
                ", conformance_levels=" + conformance_levels +
                ", oauth2Servers=" + oauth2Servers +
                ", supportsRar=" + supportsRar +
                ", supportedHashTypes=" + supportedHashTypes +
                ", documentTypes=" + documentTypes +
                '}';
    }

    public @NotBlank List<String> getConformance_levels() {
        return conformance_levels;
    }

    public void setConformance_levels(@NotBlank List<String> conformance_levels) {
        this.conformance_levels = conformance_levels;
    }

    public List<InfoConfig.OAuth2Server> getOauth2Servers() {
        return oauth2Servers;
    }

    public void setOauth2Servers(List<InfoConfig.OAuth2Server> oauth2Servers) {
        this.oauth2Servers = oauth2Servers;
    }

    public Boolean getSupportsRar() {
        return supportsRar;
    }

    public void setSupportsRar(Boolean supportsRar) {
        this.supportsRar = supportsRar;
    }

    public List<String> getSupportedHashTypes() {
        return supportedHashTypes;
    }

    public void setSupportedHashTypes(List<String> supportedHashTypes) {
        this.supportedHashTypes = supportedHashTypes;
    }

    public List<String> getDocumentTypes() {
        return documentTypes;
    }

    public void setDocumentTypes(List<String> documentTypes) {
        this.documentTypes = documentTypes;
    }

    public @NotBlank SignatureFormats getSignature_formats() {
        return signature_formats;
    }

    public void setSignature_formats(@NotBlank SignatureFormats signature_formats) {
        this.signature_formats = signature_formats;
    }

    public @NotBlank InfoConfig.SignAlgorithms getSignAlgorithms() {
        return signAlgorithms;
    }

    public void setSignAlgorithms(@NotBlank InfoConfig.SignAlgorithms signAlgorithms) {
        this.signAlgorithms = signAlgorithms;
    }

    public boolean isValidationInfo() {
        return validationInfo;
    }

    public void setValidationInfo(boolean validationInfo) {
        this.validationInfo = validationInfo;
    }

    public @NotBlank List<String> getMethods() {
        return methods;
    }

    public void setMethods(@NotBlank List<String> methods) {
        this.methods = methods;
    }

    public boolean isAsynchronousOperationMode() {
        return asynchronousOperationMode;
    }

    public void setAsynchronousOperationMode(boolean asynchronousOperationMode) {
        this.asynchronousOperationMode = asynchronousOperationMode;
    }

    public String getOauth2Issuer() {
        return oauth2Issuer;
    }

    public void setOauth2Issuer(String oauth2Issuer) {
        this.oauth2Issuer = oauth2Issuer;
    }

    public String getOauth2() {
        return oauth2;
    }

    public void setOauth2(String oauth2) {
        this.oauth2 = oauth2;
    }

    public @NotBlank List<String> getAuthType() {
        return authType;
    }

    public void setAuthType(@NotBlank List<String> authType) {
        this.authType = authType;
    }

    public @NotBlank String getDescription() {
        return description;
    }

    public void setDescription(@NotBlank String description) {
        this.description = description;
    }

    public @NotBlank String getLang() {
        return lang;
    }

    public void setLang(@NotBlank String lang) {
        this.lang = lang;
    }

    public @NotBlank String getRegion() {
        return region;
    }

    public void setRegion(@NotBlank String region) {
        this.region = region;
    }

    public @NotBlank String getLogo() {
        return logo;
    }

    public void setLogo(@NotBlank String logo) {
        this.logo = logo;
    }

    public @NotBlank String getName() {
        return name;
    }

    public void setName(@NotBlank String name) {
        this.name = name;
    }

    public @NotBlank String getSpecs() {
        return specs;
    }

    public void setSpecs(@NotBlank String specs) {
        this.specs = specs;
    }
}
