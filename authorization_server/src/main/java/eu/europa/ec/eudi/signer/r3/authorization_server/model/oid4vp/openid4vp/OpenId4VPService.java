package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.SignerError;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VPTokenInvalid;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.TrustedIssuersCertificates;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp.OpenId4VPAuthenticationToken;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;


import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp.UserAuthenticationTokenProvider;

import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.issuersigned.IssuerSignedItem;

@Service
public class OpenId4VPService {

    private static final Logger log = LoggerFactory.getLogger(OpenId4VPService.class);

    private final UserRepository repository;
    private final UserAuthenticationTokenProvider tokenProvider;
    private final TrustedIssuersCertificates trustedIssuersCertificate;

    @Autowired
    public OpenId4VPService(UserRepository repository,
                            UserAuthenticationTokenProvider tokenProvider,
                            TrustedIssuersCertificates trustedIssuersCertificate) {
        this.repository = repository;
        this.tokenProvider = tokenProvider;
        this.trustedIssuersCertificate = trustedIssuersCertificate;
    }

    public static class UserOIDTemporaryInfo {
        private final User user;
        private final String givenName;
        private final String familyName;

        public UserOIDTemporaryInfo(User user, String givenName, String familyName) {
            this.user = user;
            this.givenName = givenName;
            this.familyName = familyName;
        }

        public User getUser() {
            return this.user;
        }

        public String getGivenName() {
            return this.givenName;
        }

        public String getFamilyName() {
            return this.familyName;
        }

        public String getFullName() {
            return givenName + " " + familyName;
        }
    }

    public OpenId4VPAuthenticationToken loadUserFromVerifierResponseAndGetJWTToken(String messageFromVerifier)
            throws VerifiablePresentationVerificationException, VPTokenInvalid, NoSuchAlgorithmException, Exception {

        JSONObject vp;
        try{
            vp =  new JSONObject(messageFromVerifier);
        }
        catch (JSONException e){
            throw new Exception("The response from the Verifier doesn't contain a correctly formatted JSON string.");
        }
        VPValidator validator = new VPValidator(
                    vp,
                    VerifierClient.PresentationDefinitionId,
                    VerifierClient.PresentationDefinitionInputDescriptorsId,
                    this.trustedIssuersCertificate);
        Map<Integer, String> logsMap = new HashMap<>();
        MDoc document = validator.loadAndVerifyDocumentForVP(logsMap);
        UserOIDTemporaryInfo user = loadUserFromDocument(document);
        return addToDBandCreateAuthentication(user.getUser(), user.getGivenName(), user.getFamilyName());
    }

    public UserOIDTemporaryInfo loadUserFromDocument(MDoc document) throws VPTokenInvalid, NoSuchAlgorithmException {
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
            throw new VPTokenInvalid(SignerError.UserNotOver18, SignerError.UserNotOver18.getFormattedMessage());
        }

        if (familyName == null || givenName == null || birthDate == null || issuingCountry == null) {
            String logMessage = SignerError.VPTokenMissingValues.getCode()
                    + "(loadUserFromDocument in OpenId4VPService.class): "
                    + SignerError.VPTokenMissingValues.getDescription();
            log.error(logMessage);
            throw new VPTokenInvalid(SignerError.VPTokenMissingValues,
                    "The VP token doesn't have all the required values.");
        }

        User user = new User(familyName, givenName, birthDate, issuingCountry, issuanceAuthority, "user");
        return new UserOIDTemporaryInfo(user, givenName, familyName);
    }

    private OpenId4VPAuthenticationToken addToDBandCreateAuthentication(User userFromVerifierResponse, String givenName, String surname) {
        Optional<User> userInDatabase = repository.findByHash(userFromVerifierResponse.getHash());
        if (userInDatabase.isEmpty()) {
            repository.save(userFromVerifierResponse);
        }
        return new OpenId4VPAuthenticationToken(userFromVerifierResponse.getHash(), givenName, surname);
    }
}
