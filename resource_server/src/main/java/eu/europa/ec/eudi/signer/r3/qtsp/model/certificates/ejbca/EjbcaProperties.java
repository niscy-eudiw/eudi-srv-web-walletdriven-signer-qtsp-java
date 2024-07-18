package eu.europa.ec.eudi.signer.r3.qtsp.model.certificates.ejbca;

import java.util.List;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "ejbca")
public class EjbcaProperties {
    @NotNull
    private String cahost;
    private String clientP12ArchiveFilepath;
    private String clientP12ArchivePassword;
    private String managementCA;

    @NotNull
    private String endpoint;

    @NotNull
    private String certificateProfileName;

    @NotNull
    private String endEntityProfileName;

    @NotNull
    private String username;

    @NotNull
    private String password;

    private boolean includeChain;

    private List<CountryConfig> countries;

    public void setCountries(List<CountryConfig> countries) {
        this.countries = countries;
    }

    public String getCertificateAuthorityName(String country) {
        String def = null;
        boolean found = false;
        for (int i = 0; i < countries.size() && !found; i++) {
            CountryConfig c = this.countries.get(i);
            if (c.getCountry().equals(country)) {
                def = c.getCertificateAuthorityName();
                found = true;
            } else if (c.getCountry().equals("default")) {
                def = c.getCertificateAuthorityName();
            }
        }
        return def;
    }

    public String getCahost() {
        return cahost;
    }

    public String getClientP12ArchiveFilepath() {
        return clientP12ArchiveFilepath;
    }

    public String getClientP12ArchivePassword() {
        return clientP12ArchivePassword;
    }

    public String getManagementCA() {
        return managementCA;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public boolean getIncludeChain() {
        return includeChain;
    }

    public void setCahost(String cahost) {
        this.cahost = cahost;
    }

    public void setClientP12ArchiveFilepath(String clientP12ArchiveFilepath) {
        this.clientP12ArchiveFilepath = clientP12ArchiveFilepath;
    }

    public void setClientP12ArchivePassword(String clientP12ArchivePassword) {
        this.clientP12ArchivePassword = clientP12ArchivePassword;
    }

    public void setManagementCA(String managementCA) {
        this.managementCA = managementCA;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public void setCertificateProfileName(String certificateProfileName) {
        this.certificateProfileName = certificateProfileName;
    }

    public void setEndEntityProfileName(String endEntityProfileName) {
        this.endEntityProfileName = endEntityProfileName;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setIncludeChain(boolean includeChain) {
        this.includeChain = includeChain;
    }

    public static class CountryConfig {
        @NotNull
        private String country;

        @NotNull
        private String certificateAuthorityName;

        public String getCountry() {
            return this.country;
        }

        public void setCountry(String country) {
            this.country = country;
        }

        public String getCertificateAuthorityName() {
            return this.certificateAuthorityName;
        }

        public void setCertificateAuthorityName(String certificateAuthorityName) {
            this.certificateAuthorityName = certificateAuthorityName;
        }
    }
}
