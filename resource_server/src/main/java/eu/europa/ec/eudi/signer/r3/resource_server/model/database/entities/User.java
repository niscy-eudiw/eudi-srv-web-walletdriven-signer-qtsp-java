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

package eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities;

import java.security.MessageDigest;
import java.util.Base64;

public class User {
    private final String id;
    private final String givenName;
    private final String surname;
    private final String birthdate;
    private final String hash;
    private final String issuingCountry;
    private final String issuanceAuthority;

    public User() throws Exception{
        this.id = "user_id";
        this.givenName = "User";
        this.surname = "for testing";
        this.birthdate = "01-01-2000";
        this.issuingCountry = "PT";
        this.issuanceAuthority = "issuance authority";

        String familyNameAndGivenNameAndBirthDateAndCountry = surname + ";" + givenName + ";" + birthdate + ";" + issuingCountry;
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(familyNameAndGivenNameAndBirthDateAndCountry.getBytes());
        this.hash = Base64.getEncoder().encodeToString(result);
    }

    public String getId() {
        return id;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getSurname() {
        return surname;
    }

    public String getBirthdate() {
        return birthdate;
    }

    public String getHash() {
        return hash;
    }

    public String getIssuingCountry() {
        return issuingCountry;
    }

    public String getIssuanceAuthority() {
        return issuanceAuthority;
    }


    public String getName(){
        return this.givenName+ " "+this.surname;
    }
}
