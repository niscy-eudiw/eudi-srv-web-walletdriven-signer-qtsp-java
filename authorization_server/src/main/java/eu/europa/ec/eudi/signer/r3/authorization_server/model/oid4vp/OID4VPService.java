package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.AuthorizationRequestVariables;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.VerifierClient;
import jakarta.servlet.http.Cookie;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
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
    public AuthorizationRequestVariables authorizationRequest(String user, String url) {
        try {
            // Cookie cookie = generateCookie();
            // String sessionCookie = cookie.getValue();
            // ResponseEntity<String> responseEntity = ResponseEntity.ok(response);
            // httpResponse.addCookie(cookie);
            return this.verifierClient.initPresentationTransaction(user, VerifierClient.Authentication, url);
        } catch (Exception e) {
            log.error(e.getMessage());
            return null;
        }
    }

    private Cookie generateCookie() throws NoSuchAlgorithmException {
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        String sessionCookie = Base64.getUrlEncoder().encodeToString(result);
        Cookie cookie = new Cookie("JSESSIONID", sessionCookie);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        return cookie;
    }

}