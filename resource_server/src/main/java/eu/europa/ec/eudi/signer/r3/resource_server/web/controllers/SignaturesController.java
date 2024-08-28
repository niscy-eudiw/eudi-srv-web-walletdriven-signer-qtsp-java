package eu.europa.ec.eudi.signer.r3.resource_server.web.controllers;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import eu.europa.ec.eudi.signer.r3.resource_server.model.SignaturesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.SignaturesSignHashResponse;

@RestController
    @RequestMapping(value = "/csc/v2/signatures")
public class SignaturesController {

    @Autowired
    private SignaturesService signaturesService;

    @PostMapping(value = "/signHash", consumes = "application/json", produces = "application/json")
    public SignaturesSignHashResponse signHash(@RequestBody SignaturesSignHashRequest signHashRequest) {
        System.out.println(signHashRequest.toString());

        SignaturesSignHashResponse signaturesSignHashResponse = new SignaturesSignHashResponse();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();
        for(Map.Entry<String, Object> c : claims.entrySet()){
            System.out.println(c.getKey()+": "+c.getValue());
        }
        String user_hash = claims.get("sub").toString();
        System.out.println("User Hash: "+user_hash);

        if(!signaturesService.validateSAD(
              signHashRequest.getSAD(),
              signHashRequest.getCredentialID(),
              signHashRequest.getHashes())){
            System.out.println("SAD invalid");
            return signaturesSignHashResponse;
        }

        if(Objects.equals(signHashRequest.getOperationMode(), "A")){
            String responseID = signaturesService.asynchronousSignHash(signHashRequest.getValidity_period(), signHashRequest.getResponse_uri());
            signaturesSignHashResponse.setResponseID(responseID);
            return signaturesSignHashResponse;
        }
        else if(Objects.equals(signHashRequest.getOperationMode(), "S")){
            try {
                List<String> signatures = signaturesService.signHash(
                      signHashRequest.getCredentialID(),
                      signHashRequest.getHashes(),
                      signHashRequest.getHashAlgorithmOID(),
                      signHashRequest.getSignAlgo(),
                      signHashRequest.getSignAlgoParams());
                signaturesSignHashResponse.setSignatures(signatures);
                return signaturesSignHashResponse;
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }

        return new SignaturesSignHashResponse();
    }
}
