package eu.europa.ec.eudi.signer.r3.qtsp.DTO;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

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
    private Boolean asynchronousOperationMode;
    @NotBlank
    private List<String> methods;
    private Boolean validationInfo;

    /**
     * {
     * algos:List<String>
     * algoParams: List<String>
     * }
     */
    @NotBlank
    private JSONObject signAlgorithms;

    /**
     * {
     * formats: List<String>
     * envelope_properties: List<List<String>>
     * }
     */
    @NotBlank
    private JSONObject signature_formats;
    @NotBlank
    private List<String> conformance_levels;

    public InfoResponse() {
        this.authType = new ArrayList<>();
        this.methods = new ArrayList<>();
        this.signAlgorithms = new JSONObject();
        this.signature_formats = new JSONObject();
        this.conformance_levels = new ArrayList<>();
    }

    public String getSpecs() {
        return specs;
    }

    public void setSpecs(String specs) {
        this.specs = specs;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLogo() {
        return logo;
    }

    public void setLogo(String logo) {
        this.logo = logo;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getAuthType() {
        return authType;
    }

    public void setAuthType(List<String> authType) {
        this.authType = authType;
    }

    public String getOauth2() {
        return oauth2;
    }

    public void setOauth2(String oauth2) {
        this.oauth2 = oauth2;
    }

    public String getOauth2Issuer() {
        return oauth2Issuer;
    }

    public void setOauth2Issuer(String oauth2Issuer) {
        this.oauth2Issuer = oauth2Issuer;
    }

    public Boolean getAsynchronousOperationMode() {
        return asynchronousOperationMode;
    }

    public void setAsynchronousOperationMode(Boolean asynchronousOperationMode) {
        this.asynchronousOperationMode = asynchronousOperationMode;
    }

    public List<String> getMethods() {
        return methods;
    }

    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    public Boolean getValidationInfo() {
        return validationInfo;
    }

    public void setValidationInfo(Boolean validationInfo) {
        this.validationInfo = validationInfo;
    }

    public JSONObject getSignAlgorithms() {
        return signAlgorithms;
    }

    public void setSignAlgorithms(JSONObject signAlgorithms) {
        this.signAlgorithms = signAlgorithms;
    }

    public JSONObject getSignature_formats() {
        return signature_formats;
    }

    public void setSignature_formats(JSONObject signature_formats) {
        this.signature_formats = signature_formats;
    }

    public List<String> getConformance_levels() {
        return conformance_levels;
    }

    public void setConformance_levels(List<String> conformance_levels) {
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
}
