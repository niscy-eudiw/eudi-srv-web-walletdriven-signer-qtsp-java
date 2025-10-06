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

package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.OID4VPAuthenticationToken;
import java.util.Optional;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OpenIdForVPService {

    private static final Logger log = LoggerFactory.getLogger(OpenIdForVPService.class);
    private final UserRepository repository;
    private final VerifierClient verifierClient;

    public OpenIdForVPService(@Autowired UserRepository repository,
                              @Autowired VerifierClient verifierClient) {
        this.repository = repository;
        this.verifierClient = verifierClient;
    }

    public record UserOIDTemporaryInfo(User user, String givenName, String familyName){}

    /**
     * Function that allows to load a User object from the VP Token received from the Verifier.
     * Before creating the User object, the VP Token is validated.
     * @param messageFromVerifier a json formatted string received from the OID4VP Verifier
     * @return an unauthenticated token with information about the user to authenticate
     */

    public OID4VPAuthenticationToken loadUserFromVerifierResponseWithVerifierValidation(String messageFromVerifier) throws OID4VPException {
        log.info("Starting to load VP Token from Verifier Response...");

        JSONObject vpToken;
        try{
            vpToken =  new JSONObject(messageFromVerifier);
        }
        catch (JSONException e){
            log.error("The message from Verifier is not a well formatted JSON. {}", e.getMessage());
            throw new OID4VPException(OID4VPEnumError.RESPONSE_VERIFIER_WITH_INVALID_FORMAT, "The message from Verifier is not a valid JSON.");
        }
        log.debug("VP Token: {}", vpToken);

        String MSOMDocDeviceResponse = vpToken.getJSONObject("vp_token").getJSONArray("query_0").getString(0);
        JSONObject pidAttributes = verifierClient.validateDeviceResponse(MSOMDocDeviceResponse);
        log.info("Validated and loaded the VP Token from the Verifier response.");

		assert pidAttributes != null;
		UserOIDTemporaryInfo user = loadUserFromDocument(pidAttributes);
        log.trace("Created an object User with the information from the VP Token.");

        return OID4VPAuthenticationToken.unauthenticated(user.user().getHash(), user.givenName(), user.familyName());
    }

    private UserOIDTemporaryInfo loadUserFromDocument(JSONObject document) throws OID4VPException {
        String familyName = document.getString("family_name");
        String givenName = document.getString("given_name");
        String birthDate = String.valueOf(document.getInt("birth_date"));
        String issuingCountry = document.getString("issuing_country");
        String issuanceAuthority = document.getString("issuing_authority");
        return validateAttributesAndLoadUser(familyName, givenName, birthDate, issuingCountry, issuanceAuthority);
    }

    private UserOIDTemporaryInfo validateAttributesAndLoadUser(String familyName, String givenName, String birthDate, String issuingCountry, String issuanceAuthority) throws OID4VPException {
        if(familyName == null){
            log.error("The document in the VP Token is missing the family name.");
            throw new OID4VPException(OID4VPEnumError.VP_TOKEN_MISSING_VALUES, "Authentication failed: Your last name is missing from the submitted data. Please try again.");
        }
        if(givenName == null){
            log.error("The document in the VP Token is missing the given name.");
            throw new OID4VPException(OID4VPEnumError.VP_TOKEN_MISSING_VALUES, "Authentication failed: Your first name is missing from the submitted data. Please try again.");
        }
        if(birthDate == null){
            log.error("The document in the VP Token is missing the birthdate.");
            throw new OID4VPException(OID4VPEnumError.VP_TOKEN_MISSING_VALUES, "Authentication failed: Your birth date is missing from the submitted data. Please try again.");
        }
        if(issuingCountry == null){
            log.error("The document in the VP Token is missing the issuing country.");
            throw new OID4VPException(OID4VPEnumError.VP_TOKEN_MISSING_VALUES, "Authentication failed: The issuing country is missing from the submitted data. Please try again.");
        }
        log.info("Retrieved the required parameters from the VP Token.");

        User user = new User(familyName, givenName, birthDate, issuingCountry, issuanceAuthority, "user");
        log.info("Created an object User with the received VP Token.");

        addUserToDatabase(user);
        log.info("Added an object User to the database.");
        return new UserOIDTemporaryInfo(user, givenName, familyName);
    }



    private void addUserToDatabase(User userFromVerifierResponse) {
        Optional<User> userInDatabase = repository.findByHash(userFromVerifierResponse.getHash());
        if (userInDatabase.isEmpty()){
            repository.save(userFromVerifierResponse);
        }
    }
}
