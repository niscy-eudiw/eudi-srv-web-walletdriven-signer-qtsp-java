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

import eu.europa.ec.eudi.signer.r3.authorization_server.config.TrustedIssuersCertificateConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.OID4VPAuthenticationToken;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.issuersigned.IssuerSignedItem;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONArray;
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
    private final VerifierClient verifierClient;
    private final TransactionDataService transactionDataService;


    public OpenIdForVPService(@Autowired UserRepository repository,
                              @Autowired TrustedIssuersCertificateConfig trustedCertificatesConfig,
                              @Autowired VerifierClient verifierClient,
                              @Autowired TransactionDataService transactionDataService) {
        this.repository = repository;
        this.trustedCertificatesConfig = trustedCertificatesConfig;
        this.verifierClient = verifierClient;
        this.transactionDataService = transactionDataService;
    }

    public record UserOIDTemporaryInfo(User user, String givenName, String familyName){}

    public String getCrossDeviceRedirectLink(String urlToReturnTo, String sanitizeCookie, String serviceUrl) throws Exception {
        JSONArray transactionData = transactionDataService.getTransactionData(urlToReturnTo);
        log.info("Transaction_Data: {}", transactionData);
        String redirectLink = this.verifierClient.initCrossDeviceTransactionToVerifier(sanitizeCookie, serviceUrl, transactionData);
        log.info("Retrieved the redirect link for cross device authentication.");
        return redirectLink;
    }

    public String getSameDeviceRedirectLink(HttpServletRequest request, String sanitizeCookie, String serviceUrl) throws Exception {
        JSONArray transactionData = transactionDataService.getTransactionData(request);
        log.info("Transaction_Data: {}", transactionData);
        String redirectLink = this.verifierClient.initSameDeviceTransactionToVerifier(sanitizeCookie, serviceUrl, transactionData);
        log.info("Retrieved the redirect link for cross device authentication.");
        return redirectLink;
    }

    /**
     * Function that allows to retrieve the VP Token from the OID4VP Verifier, validate the 'transaction_data' if the value is present
     * and returns an 'OID4VPAuthenticationToken'
     * @param sessionId identifier of the session
     * @param url the request url
     * @return an unauthenticated 'OID4VPAuthenticationToken'
     */
    public OID4VPAuthenticationToken pollVPTokenAndCreateOID4VPAuthToken(String sessionId, URI url) throws OID4VPException, InterruptedException {
        String messageFromVerifier = this.verifierClient.getVPTokenFromVerifierRecursive(sessionId);
        log.info("VP Token received: {}", messageFromVerifier);

        transactionDataService.validateTransactionData(messageFromVerifier, url);
        log.info("Validated Transaction Data.");

		return loadUserFromVerifierResponseWithVerifierValidation(messageFromVerifier);
    }

    public OID4VPAuthenticationToken getVPTokenAndCreateOID4VPAuthToken(String sessionId, String code, URI url) throws OID4VPException {
        // Returns OID4VPException with a correctly formatted messages from the Error.description
        String messageFromVerifier = this.verifierClient.getVPTokenFromVerifier(sessionId, code);
        log.info("VP Token received: {}", messageFromVerifier);

        transactionDataService.validateTransactionData(messageFromVerifier, url);
        log.info("Validated Transaction Data.");

        // Returns OID4VPException with a correctly formatted messages from the Error.description
		return loadUserFromVerifierResponseWithVerifierValidation(messageFromVerifier);
    }

    /**
     * Function that allows to load a User object from the VP Token received from the Verifier.
     * Before creating the User object, the VP Token is validated.
     * @param messageFromVerifier a json formatted string received from the OID4VP Verifier
     * @return an unauthenticated token with information about the user to authenticate
     */
    private OID4VPAuthenticationToken loadUserFromVerifierResponse(String messageFromVerifier) throws OID4VPException {
        log.info("Starting to load VP Token from Verifier Response...");

        JSONObject vpToken;
        try{
            vpToken =  new JSONObject(messageFromVerifier);
        }
        catch (JSONException e){
            log.error("The message from Verifier is not a well formatted JSON. {}",e.getMessage());
            throw new OID4VPException(OID4VPEnumError.RESPONSE_VERIFIER_WITH_INVALID_FORMAT, "The message from Verifier is not a valid JSON.");
        }
        log.debug("VP Token: {}", vpToken);

        VPValidator validator = new VPValidator(vpToken, VerifierClient.PRESENTATION_DEFINITION_ID, VerifierClient.PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID, this.trustedCertificatesConfig);
        MDoc document = validator.loadAndVerifyDocumentForVP();
        log.info("Validated and loaded the VP Token from the Verifier response.");

        UserOIDTemporaryInfo user = loadUserFromDocument(document);
        log.trace("Created an object User with the information from the VP Token.");

        return OID4VPAuthenticationToken.unauthenticated(user.user().getHash(), user.givenName(), user.familyName());
    }

    private OID4VPAuthenticationToken loadUserFromVerifierResponseWithVerifierValidation(String messageFromVerifier) throws OID4VPException {
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

        String MSOMDocDeviceResponse = vpToken.getJSONArray("vp_token").getString(0);
        JSONObject pidAttributes = verifierClient.validateDeviceResponse(MSOMDocDeviceResponse);
        log.info("Validated and loaded the VP Token from the Verifier response.");

		assert pidAttributes != null;
		UserOIDTemporaryInfo user = loadUserFromDocument(pidAttributes);
        log.trace("Created an object User with the information from the VP Token.");

        OID4VPAuthenticationToken unauthenticatedToken = OID4VPAuthenticationToken.unauthenticated(user.user().getHash(), user.givenName(), user.familyName());
        log.info("Created an unauthenticated OID4VP Token.");
        return unauthenticatedToken;
    }

    private UserOIDTemporaryInfo loadUserFromDocument(JSONObject document) throws OID4VPException {
        String familyName = document.getString("family_name");
        String givenName = document.getString("given_name");
        String birthDate = String.valueOf(document.getInt("birth_date"));
        String issuingCountry = document.getString("issuing_country");
        String issuanceAuthority = document.getString("issuing_authority");
        return validateAttributesAndLoadUser(familyName, givenName, birthDate, issuingCountry, issuanceAuthority);
    }

    private UserOIDTemporaryInfo loadUserFromDocument(MDoc document) throws OID4VPException {
        String docType = document.getDocType().getValue();
        List<IssuerSignedItem> l = document.getIssuerSignedItems(docType);

        String familyName = null;
        String givenName = null;
        String birthDate = null;
        String issuingCountry = null;
        String issuanceAuthority = null;
        for (IssuerSignedItem el : l) {
            switch (el.getElementIdentifier().getValue()) {
                case "family_name" -> familyName = el.getElementValue().toString();
                case "given_name" -> givenName = el.getElementValue().toString();
                case "birth_date" -> birthDate = el.getElementValue().toString();
                case "issuing_authority" -> issuanceAuthority = el.getElementValue().toString();
                case "issuing_country" -> issuingCountry = el.getElementValue().toString();
            }
        }

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
