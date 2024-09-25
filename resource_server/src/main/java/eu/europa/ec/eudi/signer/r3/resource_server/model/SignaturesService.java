package eu.europa.ec.eudi.signer.r3.resource_server.model;

import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.CredentialsRepository;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import eu.europa.esig.dss.enumerations.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SignaturesService {
    private final CredentialsRepository credentialsRepository;
    private final HsmService hsmService;

    public SignaturesService(@Autowired HsmService hsmService,
                             @Autowired CredentialsRepository credentialsRepository){
        this.credentialsRepository = credentialsRepository;
        this.hsmService = hsmService;
    }

    public boolean validateSignatureRequest(String userHash, String credentialIDRequest, String credentialIDAuthorized,
                                            int numSignaturesRequest, int numSignaturesAuthorized, String hashAlgorithmOIDRequest,
                                            String hashAlgorithmOIDAuthorized, List<String> hashesRequest, List<String> hashesAuthorized){
        if(!credentialIDRequest.equals(credentialIDAuthorized)){
            System.out.println(credentialIDRequest+"="+credentialIDAuthorized);
            return false;
        }
        if(numSignaturesRequest != numSignaturesAuthorized) {
            System.out.println(numSignaturesRequest+"="+numSignaturesAuthorized);
            return false;
        }
        if(!hashAlgorithmOIDRequest.equals(hashAlgorithmOIDAuthorized)){
            System.out.println(hashAlgorithmOIDRequest+"="+hashAlgorithmOIDAuthorized);
            return false;
        }

        Optional<String> credentials = this.credentialsRepository.findByUserIDAndId(userHash, credentialIDRequest);
        if(credentials.isEmpty()){
            System.out.println("CredentialID does not bellong to user.");
            return false;
        }

        if (hashesRequest == null || hashesAuthorized == null) return false;
        if (hashesRequest.size() != hashesAuthorized.size()) return false;
        if (hashesRequest.size() != numSignaturesRequest){
            System.out.println(hashesRequest.size()+"="+numSignaturesRequest);
            return false;
        }

        //Collections.sort(hashesRequest);
        //Collections.sort(hashesAuthorized);

        for (String s1: hashesRequest){
            System.out.println(s1);
        }
        for (String s2: hashesAuthorized){
            System.out.println(s2);
        }

        return hashesRequest.equals(hashesAuthorized);
    }

    // to be implemented
    public String asynchronousSignHash(int validity_period, String response_uri){
        System.out.println("Currently Asynchronous responses are not supported");
        return "responseID";
    }

    public List<String> signHash(String credentialID, List<String> hashes, String hashAlgorithmID, String signAlgo, String signAlgoParams) throws Exception {

        Optional<Credentials> credentialsOptional = this.credentialsRepository.findById(credentialID);
        if(credentialsOptional.isEmpty()) return new ArrayList<>();
        Credentials credential = credentialsOptional.get();

        if (!credential.getKeyAlgo().contains(signAlgo)){
            System.out.println("Signing Algorithm indicated is not supported by the signing key chosen.");
            return new ArrayList<>();
        }

        String signatureAlgorithm = getSignatureAlgorithm(signAlgo, signAlgoParams, hashAlgorithmID);

        String privateKeyBase64 = credential.getPrivateKey();
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);

        List<String> signatures = new ArrayList<>();
        for (String dtbs : hashes) {
            String dtbsDecoded = URLDecoder.decode(dtbs, StandardCharsets.UTF_8);
            byte[] dtbsBytes = Base64.getDecoder().decode(dtbsDecoded);
            byte[] signatureBytes = this.hsmService.signWithSomeAlgorithm(privateKeyBytes, dtbsBytes, signatureAlgorithm);
            String signature = Base64.getEncoder().encodeToString(signatureBytes);
            signatures.add(signature);
        }
        return signatures;
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
            System.out.println(e.getMessage());
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
