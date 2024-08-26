package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.AuthorizationRequestVariables;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.VerifierClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OID4VPService {
    private static final Logger log = LoggerFactory.getLogger(OID4VPService.class);
    private final VerifierClient verifierClient;

    public OID4VPService(@Autowired VerifierClient verifierClient){
        this.verifierClient = verifierClient;
    }

    // Executes the Authorization Request interaction
    public AuthorizationRequestVariables authorizationRequest(String user, String url, String return_to_uri) {
        try {
            return this.verifierClient.initPresentationTransaction(user, VerifierClient.Authentication, url, return_to_uri);
        } catch (Exception e) {
            log.error(e.getMessage());
            return null;
        }
    }
}