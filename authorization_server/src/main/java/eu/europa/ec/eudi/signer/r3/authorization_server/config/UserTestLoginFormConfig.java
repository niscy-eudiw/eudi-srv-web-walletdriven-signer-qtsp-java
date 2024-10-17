package eu.europa.ec.eudi.signer.r3.authorization_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix="user-login-form")
public class UserTestLoginFormConfig {
	private String familyName;
	private String givenName;
	private String birthDate;
	private String issuingCountry;
	private String issuanceAuthority;
	private String role;
	private String password;

	public String getFamilyName() {
		return familyName;
	}

	public void setFamilyName(String familyName) {
		this.familyName = familyName;
	}

	public String getGivenName() {
		return givenName;
	}

	public void setGivenName(String givenName) {
		this.givenName = givenName;
	}

	public String getBirthDate() {
		return birthDate;
	}

	public void setBirthDate(String birthDate) {
		this.birthDate = birthDate;
	}

	public String getIssuingCountry() {
		return issuingCountry;
	}

	public void setIssuingCountry(String issuingCountry) {
		this.issuingCountry = issuingCountry;
	}

	public String getIssuanceAuthority() {
		return issuanceAuthority;
	}

	public void setIssuanceAuthority(String issuanceAuthority) {
		this.issuanceAuthority = issuanceAuthority;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
