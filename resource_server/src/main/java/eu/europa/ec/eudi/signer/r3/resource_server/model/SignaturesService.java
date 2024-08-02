package eu.europa.ec.eudi.signer.r3.resource_server.model;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.CertificatesService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.CredentialsRepository;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;

import eu.europa.esig.dss.enumerations.*;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class SignaturesService {

    private final CertificatesService certificatesService;
    private final CredentialsRepository credentialsRepository;
    private final HsmService hsmService;

    public SignaturesService(
          @Autowired HsmService hsmService,
          @Autowired EjbcaService ejbcaService,
          @Autowired CredentialsRepository credentialsRepository
    ) throws Exception{
        this.credentialsRepository = credentialsRepository;
        this.certificatesService = new CertificatesService(hsmService, ejbcaService);
        this.hsmService = hsmService;
        DefaultVariables defaultVariables = new DefaultVariables(this.credentialsRepository, this.certificatesService);
        defaultVariables.addDefaultCredentials();
    }

    // to be implemented: probably will also need information about the document to be signed, to verify if it was the same requested
    public boolean validateSAD(String SAD, String credentialID, List<String> hashes){
        return true;
    }

    // to be implemented
    public String asynchronousSignHash(int validity_period, String response_uri){
        System.out.println("Currently Asynchronous responses are not supported");
        return "responseID";
    }


    // to be implemented
    public List<String> signHash(
          String credentialID,
          List<String> hashes,
          String hashAlgorithmID,
          String signAlgo,
          String signAlgoParams) throws Exception {

        Optional<Credentials> credentialsOptional = this.credentialsRepository.findById(credentialID);
        if(credentialsOptional.isEmpty()) return new ArrayList<>();
        Credentials credential = credentialsOptional.get();

        if (!credential.getKeyAlgo().contains(signAlgo)){
            System.out.println("Signing Algorithm indicated is not supported by the signing key chosen.");
            return new ArrayList<>();
        }

        String signatureAlgorithm = getSignatureAlgorithm(signAlgo, signAlgoParams, hashAlgorithmID);

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
                    Signature sig = Signature.getInstance(signatureAlgorithm);
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
        else{
            String privateKeyBase64 = credential.getPrivateKey();
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);

            List<String> signatures = new ArrayList<>();
            for (String dtbs : hashes) {
                byte[] dtbsBytes = Base64.getDecoder().decode(dtbs);
                byte[] signatureBytes = this.hsmService.signWithSomeAlgorithm(privateKeyBytes, dtbsBytes, signatureAlgorithm);
                String signature = Base64.getEncoder().encodeToString(signatureBytes);
                signatures.add(signature);
            }
            return signatures;
        }
    }
    
    public String getSignatureAlgorithm(String signAlgo, String signAlgoParams, String hashAlgorithmID){
        DefaultAlgorithmNameFinder algFinder = new DefaultAlgorithmNameFinder();
        ASN1ObjectIdentifier signAlgoId = new ASN1ObjectIdentifier(signAlgo);

        try{
            SignatureAlgorithm signAlgorithm = SignatureAlgorithm.forOID(signAlgoId.getId());
            ASN1ObjectIdentifier a = new ASN1ObjectIdentifier(signAlgorithm.getOid());
            System.out.println("The algorithm defined in the signAlgo parameter already contains an hash algorithm.");
            System.out.println(algFinder.getAlgorithmName(a));
            return algFinder.getAlgorithmName(a);
        }
        catch (IllegalArgumentException e){
            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forOID(signAlgo);
            System.out.println(encryptionAlgorithm.getName());

            DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(hashAlgorithmID);
            System.out.println(digestAlgorithm.getName());

            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
            ASN1ObjectIdentifier a = new ASN1ObjectIdentifier(signatureAlgorithm.getOid());
            System.out.println(algFinder.getAlgorithmName(a));
            return algFinder.getAlgorithmName(a);
        }
    }
}
