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

package eu.europa.ec.eudi.signer.r3.resource_server.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "info")
public class InfoConfig {

    private String specs;
    private String name;
    private String logo;
    private String region;
    private String lang;
    private String description;
    private List<String> authType;
    private String oauth2;
    private boolean asynchronousOperationMode;
    private List<String> methods;
    private boolean validationInfo;
    private SignAlgorithms signAlgorithms;
    private Map<String, List<String>> signature_formats;
    private List<String> conformance_levels;

    public static class SignAlgorithms{
        private List<String> algos;
        private List<String> algoParams;

        public SignAlgorithms(){
            this.algos = new ArrayList<>();
            this.algoParams = new ArrayList<>();
        }

        public List<String> getAlgos() {
            return algos;
        }

        public void setAlgos(List<String> algos) {
            this.algos = algos;
        }

        public List<String> getAlgoParams() {
            return algoParams;
        }

        public void setAlgoParams(List<String> algoParams) {
            this.algoParams = algoParams;
        }

        @Override
        public String toString() {
            return "SignAlgorithms{" +
                  "algos=" + algos +
                  ", algoParams=" + algoParams +
                  '}';
        }
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

    public boolean getAsynchronousOperationMode() {
        return asynchronousOperationMode;
    }

    public void setAsynchronousOperationMode(boolean asynchronousOperationMode) {
        this.asynchronousOperationMode = asynchronousOperationMode;
    }

    public List<String> getMethods() {
        return methods;
    }

    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    public boolean getValidationInfo() {
        return validationInfo;
    }

    public void setValidationInfo(boolean validationInfo) {
        this.validationInfo = validationInfo;
    }

    public SignAlgorithms getSignAlgorithms() {
        return signAlgorithms;
    }

    public void setSignAlgorithms(SignAlgorithms signAlgorithms) {
        this.signAlgorithms = signAlgorithms;
    }

    public Map<String, List<String>> getSignature_formats() {
        return signature_formats;
    }

    public void setSignature_formats(Map<String, List<String>> signature_formats) {
        this.signature_formats = signature_formats;
    }

    public List<String> getConformance_levels() {
        return conformance_levels;
    }

    public void setConformance_levels(List<String> conformance_levels) {
        this.conformance_levels = conformance_levels;
    }

    @Override
    public String toString() {
        return "InfoProperties{" +
              "specs='" + specs + '\'' +
              ", name='" + name + '\'' +
              ", logo='" + logo + '\'' +
              ", region='" + region + '\'' +
              ", lang='" + lang + '\'' +
              ", description='" + description + '\'' +
              ", authType=" + authType +
              ", oauth2='" + oauth2 + '\'' +
              ", asynchronousOperationMode=" + asynchronousOperationMode +
              ", methods=" + methods +
              ", validationInfo=" + validationInfo +
              ", signAlgorithms=" + signAlgorithms.toString() +
              ", signature_formats=" + signature_formats +
              ", conformance_levels=" + conformance_levels +
              '}';
    }
}
