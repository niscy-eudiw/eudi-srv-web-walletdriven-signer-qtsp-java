package eu.europa.ec.eudi.signer.r3.qtsp.Controllers;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import eu.europa.ec.eudi.signer.r3.qtsp.Model.SignaturesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.r3.qtsp.DTO.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.SignaturesSignHashResponse;

@RestController
@RequestMapping(value = "/csc/v2/signatures")
public class SignaturesController {

    @Autowired
    private SignaturesService signaturesService;

    @PostMapping(value = "/signHash", consumes = "application/json", produces = "application/json")
    public SignaturesSignHashResponse signHash(@RequestBody SignaturesSignHashRequest signHashRequest) {
        System.out.println(signHashRequest.toString());

        if(!signaturesService.validateSAD(signHashRequest.getSAD(), signHashRequest.getCredentialID())){
            System.out.println("SAD invalid");
            return new SignaturesSignHashResponse();
        }

        if(Objects.equals(signHashRequest.getOperationMode(), "A")){
            System.out.println("Currently Asynchronous responses are not supported");
            return new SignaturesSignHashResponse();
        }

        SignaturesSignHashResponse response = new SignaturesSignHashResponse();
        List<String> signatures =
                signaturesService.signHash(
                        signHashRequest.getCredentialID(),
                        signHashRequest.getHashes(),
                        signHashRequest.getHashAlgorithmOID(),
                        signHashRequest.getSignAlgo(),
                        signHashRequest.getSignAlgoParams());

        response.setSignatures(signatures);
        return response;
    }
}
