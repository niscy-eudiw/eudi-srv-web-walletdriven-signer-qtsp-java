package eu.europa.ec.eudi.signer.r3.resource_server.web.controllers;

import eu.europa.ec.eudi.signer.r3.resource_server.model.SignaturesService;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.SignaturesSignHashResponse;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(value = "/csc/v2/signatures")
public class SignaturesController {

    private final SignaturesService signaturesService;
    private static final Logger logger = LoggerFactory.getLogger(SignaturesController.class);

    public SignaturesController(@Autowired SignaturesService signaturesService) {
        this.signaturesService = signaturesService;
    }

    @PostMapping(value = "/signHash", consumes = "application/json", produces = "application/json")
    public SignaturesSignHashResponse signHash(@RequestBody SignaturesSignHashRequest signHashRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();
        String userHash = claims.get("sub").toString();
        logger.info("Request received at /csc/v2/credentials/list with the body {} from the user {}", signHashRequest.toString(), userHash);

        StringBuilder stringBuilder = new StringBuilder();
        for(Map.Entry<String, Object> c: claims.entrySet()){
            stringBuilder.append(c.getKey()).append(": ").append(c.getValue()).append("/n");
        }
        logger.trace("Access Token Claims: {}", stringBuilder.toString());

        String credentialIDAuthorized = claims.get("credentialID").toString();
        logger.trace("credentialIDAuthorized: {}", credentialIDAuthorized);
        int numSignaturesAuthorized = Integer.parseInt(claims.get("numSignatures").toString());
        logger.trace("numSignaturesAuthorized: {}", numSignaturesAuthorized);
        String hashAlgorithmOIDAuthorized = claims.get("hashAlgorithmOID").toString();
        logger.trace("hashAlgorithmOIDAuthorized: {}", hashAlgorithmOIDAuthorized);
        String hashesString = claims.get("hashes").toString();
        logger.trace("hashesString: {}", hashesString);
        String[] hashesAuthorizedArray = hashesString.split(",");
        Arrays.sort(hashesAuthorizedArray);
        List<String> hashesAuthorized = List.of(hashesAuthorizedArray);

        try {
            List<String> hashesRequested = signHashRequest.getHashes();
            Collections.sort(hashesRequested);
            for(String s: hashesRequested){
                logger.trace(s);
            }

            if(!signaturesService.validateSignatureRequest(userHash, signHashRequest.getCredentialID(), credentialIDAuthorized, signHashRequest.getHashes().size(), numSignaturesAuthorized, signHashRequest.getHashAlgorithmOID(), hashAlgorithmOIDAuthorized, hashesRequested, hashesAuthorized)){
                logger.error("The Authorization Header doesn't authorize the current Signature Request.");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request: the authorization header doesn't authorize the signature request.");
            }

            if(Objects.equals(signHashRequest.getOperationMode(), "A")){
                logger.error("Currently Asynchronous responses are not supported");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request: asynchronous responses are not supported.");
            }
            else if(Objects.equals(signHashRequest.getOperationMode(), "S")){
                SignaturesSignHashResponse signaturesSignHashResponse = new SignaturesSignHashResponse();
                List<String> signatures = signaturesService.signHash(signHashRequest.getCredentialID(), signHashRequest.getHashes(), signHashRequest.getHashAlgorithmOID(), signHashRequest.getSignAlgo(), signHashRequest.getSignAlgoParams());
                signaturesSignHashResponse.setSignatures(signatures);
                logger.info("Set the Signatures Values in the Response.");
                return signaturesSignHashResponse;
            }
            else throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request");
        }
        catch (Exception e){
            logger.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request");
        }
    }
}
