package eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities;

import java.security.MessageDigest;
import java.util.Base64;

public class User {
    private String id;
    private String givenName;
    private String surname;
    private String birthdate;
    private String hash;
    private String issuingCountry;
    private String issuanceAuthority;

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
