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

package eu.europa.ec.eudi.signer.r3.authorization_server.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;

/*@ConditionalOnProperty(prefix = "user-login-form", name = "enabled", havingValue = "true", matchIfMissing = true)
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

	@Override
	public String toString() {
		return "UserTestLoginFormConfig{" +
			  "familyName='" + familyName + '\'' +
			  ", givenName='" + givenName + '\'' +
			  ", birthDate='" + birthDate + '\'' +
			  ", issuingCountry='" + issuingCountry + '\'' +
			  ", issuanceAuthority='" + issuanceAuthority + '\'' +
			  ", role='" + role + '\'' +
			  ", password='" + password + '\'' +
			  '}';
	}

	public boolean isEmpty(){
		return familyName==null || givenName ==null || birthDate == null || issuanceAuthority == null || issuingCountry == null || password == null;
	}
}*/
