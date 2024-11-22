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

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.TrustedIssuersCertificateConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.SignerError;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VPTokenInvalidException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.OID4VPAuthenticationToken;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.issuersigned.IssuerSignedItem;
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
    private final TrustedIssuersCertificateConfig trustedCertificatesConfig;

    public OpenIdForVPService(@Autowired UserRepository repository,
                              @Autowired TrustedIssuersCertificateConfig trustedCertificatesConfig) {
        this.repository = repository;
        this.trustedCertificatesConfig = trustedCertificatesConfig;
    }

    public record UserOIDTemporaryInfo(User user, String givenName, String familyName){}

    /**
     * Function that allows to load a User object from the VP Token received from the Verifier.
     * Before creating the User object, the VP Token is validated.
     * @param messageFromVerifier a json formatted string received from the OID4VP Verifier
     * @return an unauthenticated token with information about the user to authenticate
     * @throws VerifiablePresentationVerificationException exception thrown if the VP Token's verification failed
     */
    public OID4VPAuthenticationToken loadUserFromVerifierResponse(String messageFromVerifier) throws VPTokenInvalidException,
          VerifiablePresentationVerificationException, NoSuchAlgorithmException {
        log.info("Starting to load VP Toke from response...");
        JSONObject vpToken;
        try{
            vpToken =  new JSONObject(messageFromVerifier);
        }
        catch (JSONException e){
            log.error(e.getMessage());
            throw new VPTokenInvalidException(SignerError.UnexpectedError,
                  "The response from the Verifier doesn't contain a correctly formatted JSON string.");
        }
        log.trace("VP Token: {}", vpToken);

        VPValidator validator = new VPValidator(vpToken, VerifierClient.PresentationDefinitionId,
                    VerifierClient.PresentationDefinitionInputDescriptorsId, this.trustedCertificatesConfig);
        Map<Integer, String> logsMap = new HashMap<>();
        MDoc document = validator.loadAndVerifyDocumentForVP(logsMap);
        log.info("Successfully validated and loaded the VP Token from the verifier response.");

        UserOIDTemporaryInfo user = loadUserFromDocument(document);
        log.trace("Successfully created an object User with the information from the VP Token.");

        return OID4VPAuthenticationToken.unauthenticated(user.user().getHash(), user.givenName(), user.familyName());
    }

    private UserOIDTemporaryInfo loadUserFromDocument(MDoc document) throws VPTokenInvalidException, NoSuchAlgorithmException {
        List<IssuerSignedItem> l = document.getIssuerSignedItems(document.getDocType().getValue());

        String familyName = null;
        String givenName = null;
        String birthDate = null;
        String issuingCountry = null;
        String issuanceAuthority = null;
        boolean ageOver18 = false;
        for (IssuerSignedItem el : l) {
            switch (el.getElementIdentifier().getValue()) {
                case "family_name" -> familyName = el.getElementValue().getValue().toString();
                case "given_name" -> givenName = el.getElementValue().getValue().toString();
                case "birth_date" -> birthDate = el.getElementValue().getValue().toString();
                case "age_over_18" -> ageOver18 = (boolean) el.getElementValue().getValue();
                case "issuing_authority" -> issuanceAuthority = el.getElementValue().getValue().toString();
                case "issuing_country" -> issuingCountry = el.getElementValue().getValue().toString();
            }
        }

        if (!ageOver18) {
            log.error(SignerError.UserNotOver18.getDescription());
            throw new VPTokenInvalidException(SignerError.UserNotOver18, SignerError.UserNotOver18.getFormattedMessage());
        }

        if (familyName == null || givenName == null || birthDate == null || issuingCountry == null) {
            log.error("{}(loadUserFromDocument in OpenId4VPService.class): {}",
                  SignerError.VPTokenMissingValues.getCode(), SignerError.VPTokenMissingValues.getDescription());
            throw new VPTokenInvalidException(SignerError.VPTokenMissingValues,
                  "The VP token doesn't have all the required values.");
        }
        log.info("Successfully retrieve the required parameters from the VP Token.");

        User user = new User(familyName, givenName, birthDate, issuingCountry, issuanceAuthority, "user");
        log.info("Successfully created an object User with the received VP Token.");
        addUserToDatabase(user);
        log.info("Added User to the database.");
        return new UserOIDTemporaryInfo(user, givenName, familyName);
    }

    private void addUserToDatabase(User userFromVerifierResponse) {
        Optional<User> userInDatabase = repository.findByHash(userFromVerifierResponse.getHash());
        if (userInDatabase.isEmpty()){
            repository.save(userFromVerifierResponse);
        }
    }
}
