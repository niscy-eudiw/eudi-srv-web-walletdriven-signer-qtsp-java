package eu.europa.ec.eudi.signer.r3.qtsp.model;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import eu.europa.ec.eudi.signer.r3.qtsp.model.certificates.CertificatesService;
import eu.europa.ec.eudi.signer.r3.qtsp.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.repositories.CredentialsRepository;
import eu.europa.ec.eudi.signer.r3.qtsp.model.keys.hsm.HsmService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SignaturesService {

    private final CertificatesService certificatesService;
    private final CredentialsRepository credentialsRepository;

    public SignaturesService(
          @Autowired HsmService hsmService,
          @Autowired EjbcaService ejbcaService,
          @Autowired CredentialsRepository credentialsRepository
    ) throws Exception{
        this.credentialsRepository = credentialsRepository;
        this.certificatesService = new CertificatesService(hsmService, ejbcaService);
        DefaultVariables defaultVariables = new DefaultVariables(this.credentialsRepository, this.certificatesService);
        defaultVariables.addDefaultCredentials();
    }

    // to be implemented: probably will also need information about the document to be signed, to verify if it was the same requested
    public boolean validateSAD(String SAD, String credentialID){
        return true;
    }

    // to be implemented
    public List<String> signHash(String credentialID, List<String> hashes, String hashAlgorithmID, String signAlgo, String signAlgoParams) throws Exception {
        Optional<Credentials> credentialsOptional = this.credentialsRepository.findById(credentialID);

        if(credentialsOptional.isEmpty()) return new ArrayList<>();

        Credentials credential = credentialsOptional.get();
        if(credential.getId().equals("cred1")){
            String privateKeyBase64 = credential.getPrivateKey();
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec spec2 = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey sKey = keyFactory.generatePrivate(spec2);

            List<String> signatures = new ArrayList<>();
            for (String dtbs : hashes) {
                try {
                    byte[] dtbs_bytes = Base64.getDecoder().decode(dtbs);
                    Signature sig = Signature.getInstance("SHA256WithRSA");
                    sig.initSign(sKey);
                    sig.update(dtbs_bytes);
                    byte[] signature_bytes = sig.sign();
                    String signature = Base64.getEncoder().encodeToString(signature_bytes);
                    signatures.add(signature);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            return signatures;
        }
        else return new ArrayList<>();
    }
}
