package eu.europa.ec.eudi.signer.r3.qtsp.Controllers;

import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsInfo.CredentialsInfoCert;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsInfoAuth;
import eu.europa.ec.eudi.signer.r3.qtsp.Model.CredentialsService;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsListRequest;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsListResponse;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsInfo.CredentialsInfoKey;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsInfo.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsInfo.CredentialsInfoResponse;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping(value = "/csc/v2/credentials")
public class CredentialsController {

    @Autowired
    private CredentialsService credentialsService;

    @PostMapping(value = "/list", consumes = "application/json", produces = "application/json")
    public CredentialsListResponse list(@RequestBody CredentialsListRequest listRequestDTO) {
        System.out.println(listRequestDTO.toString());

        // onlyValid = listRequestDTO.getOnlyValid() && is supported by the QTSP:
        boolean onlyValid = listRequestDTO.getOnlyValid();

        CredentialsListResponse clr = new CredentialsListResponse();

        List<String> availableCredentialsId = credentialsService.getAvailableCredentialsID(listRequestDTO.getUserID(), onlyValid);
        clr.setCredentialIDs(availableCredentialsId);

        if(listRequestDTO.getCredentialInfo()){
            // return the main information included in the public key certificate and the public key certificate or the certificate chain.
            List<CredentialsListResponse.CredentialInfo> ci = credentialsService.getCredentialInfo(listRequestDTO.getCertificates(), listRequestDTO.getCertInfo(), listRequestDTO.getAuthInfo(), onlyValid);
            clr.setCredentialInfos(ci);
        }
        return clr;
    }

    @PostMapping(value = "/info", consumes = "application/json", produces = "application/json")
    public CredentialsInfoResponse info(@RequestBody CredentialsInfoRequest infoRequestDTO) {
        System.out.println(infoRequestDTO.toString());

        CredentialsInfoResponse cir = new CredentialsInfoResponse();
        CredentialsListResponse.CredentialInfo ci =
                credentialsService.getCredentialInfoFromSingleCredential(
                        infoRequestDTO.getCredentialID(),
                        infoRequestDTO.getCertificates(),
                        infoRequestDTO.getCertInfo(),
                        infoRequestDTO.getAuthInfo());

        cir.setDescription(ci.getDescription());
        cir.setSignatureQualifier(ci.getSignatureQualifier());
        cir.setSCAL(ci.getSCAL());
        cir.setMultisign(ci.getMultisign());
        cir.setKey(ci.getKey());
        cir.setCert(ci.getCert());
        cir.setAuth(ci.getAuth());
        return cir;
    }
}
