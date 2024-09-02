package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.SignerError;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VPTokenInvalid;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.TrustedIssuersCertificates;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.AuthenticationManagerToken;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.issuersigned.IssuerSignedItem;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OpenId4VPService {

    private static final Logger log = LoggerFactory.getLogger(OpenId4VPService.class);

    private final UserRepository repository;
    private final TrustedIssuersCertificates trustedIssuersCertificate;

    @Autowired
    public OpenId4VPService(UserRepository repository,
                            TrustedIssuersCertificates trustedIssuersCertificate) {
        this.repository = repository;
        this.trustedIssuersCertificate = trustedIssuersCertificate;
    }

    public record UserOIDTemporaryInfo(User user, String givenName, String familyName) {

        public String getFullName() {
                return givenName + " " + familyName;
            }

    }

    public AuthenticationManagerToken loadUserFromVerifierResponse(String messageFromVerifier)
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
        addToDB(user.user());
        return AuthenticationManagerToken.unauthenticated(user.user().getHash(), user.givenName(), user.familyName());
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

    private void addToDB(User userFromVerifierResponse) {
        Optional<User> userInDatabase = repository.findByHash(userFromVerifierResponse.getHash());
        if (userInDatabase.isEmpty()) repository.save(userFromVerifierResponse);
    }
}
