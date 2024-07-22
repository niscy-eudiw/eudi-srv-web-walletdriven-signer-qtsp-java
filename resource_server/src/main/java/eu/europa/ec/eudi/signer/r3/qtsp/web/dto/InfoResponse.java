package eu.europa.ec.eudi.signer.r3.qtsp.web.dto;

import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.eudi.signer.r3.qtsp.config.InfoConfig;

import jakarta.validation.constraints.NotBlank;

public class InfoResponse {
    @NotBlank
    private String specs = "2.0.0.0";
    @NotBlank
    private String name = "Trust Provider Signer R3 QTSP";
    @NotBlank
    private String logo = "img";
    @NotBlank
    private String region = "EU";
    @NotBlank
    private String lang = "en-US";
    @NotBlank
    private String description = "test qtsp";
    @NotBlank
    private List<String> authType;
    private String oauth2;
    private String oauth2Issuer;
    private boolean asynchronousOperationMode;
    @NotBlank
    private List<String> methods;
    private boolean validationInfo;
    @NotBlank
    private InfoConfig.SignAlgorithms signAlgorithms;

    /**
     * {
     * formats: List<String>
     * envelope_properties: List<List<String>>
     * }
     */
    @NotBlank
    private SignatureFormats signature_formats;

    private static class SignatureFormats{
        private List<String> formats;
        private List<List<String>> envelope_properties;

        public SignatureFormats(){
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

    @NotBlank
    private List<String> conformance_levels;

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
                '}';
    }

    public @NotBlank List<String> getConformance_levels() {
        return conformance_levels;
    }

    public void setConformance_levels(@NotBlank List<String> conformance_levels) {
        this.conformance_levels = conformance_levels;
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
