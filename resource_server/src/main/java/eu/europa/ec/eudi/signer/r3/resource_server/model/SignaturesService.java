package eu.europa.ec.eudi.signer.r3.resource_server.model;

import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.CredentialsRepository;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import eu.europa.esig.dss.enumerations.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SignaturesService {
    private final CredentialsRepository credentialsRepository;
    private final HsmService hsmService;
    private static final Logger logger = LoggerFactory.getLogger(SignaturesService.class);

    public SignaturesService(@Autowired HsmService hsmService,
                             @Autowired CredentialsRepository credentialsRepository){
        this.credentialsRepository = credentialsRepository;
        this.hsmService = hsmService;
    }

    /**
     * Function responsible for validating if a signature request is valid,
     * by comparing the requested values with the values in the authorization bearer
     * @return boolean
     */
    public boolean validateSignatureRequest(String userHash, String credentialIDRequested, String credentialIDAuthorized,
                                            int numSignaturesRequested, int numSignaturesAuthorized,
                                            String hashAlgorithmOIDRequested, String hashAlgorithmOIDAuthorized,
                                            List<String> hashesRequested, List<String> hashesAuthorized){
        if(!credentialIDRequested.equals(credentialIDAuthorized)){
            logger.error("The credentialId requested doesn't match the credentialId authorized.");
            return false;
        }
        if(numSignaturesRequested != numSignaturesAuthorized) {
            logger.error("The number of signatures requested doesn't match the number of signatures authorized.");
            return false;
        }
        if(!hashAlgorithmOIDRequested.equals(hashAlgorithmOIDAuthorized)){
            logger.error("The hashAlgorithmOID requested doesn't match the hashAlgorithmOID authorized.");
            return false;
        }
        Optional<String> credentials = this.credentialsRepository.findByUserIDAndId(userHash, credentialIDRequested);
        if(credentials.isEmpty()){
            logger.error("The credentialId requested doesn't belong to the user.");
            return false;
        }
        if (hashesRequested == null || hashesAuthorized == null){
            logger.error("One or both of the hash values are missing.");
            return false;
        }
        if (hashesRequested.size() != hashesAuthorized.size()){
            logger.error("The number of the hash values requested to sign doesn't match the number of hash values authorized.");
            return false;
        }
        if (hashesRequested.size() != numSignaturesRequested){
            logger.error("The number of hash values requested to sign doesn't match the number of signatures requested.");
            return false;
        }
        if(!hashesRequested.equals(hashesAuthorized)){
            logger.error("The hashes requested are different from the hashes authorized.");
            return false;
        }
        return true;
    }

    /**
     * Function that can be used to calculate the signature value of given hashes
     * @param credentialID the identifier of the credential (certificate and key pair) to be used
     * @param hashes a list of the hash value of a documents to be signed
     * @param hashAlgorithmOID the oid of the hash algorithm used to obtain the hash value
     * @param signAlgo the signature algorithm to be used and that should be supported by the key pair to use
     * @param signAlgoParams additional parameters of the signature algorithms (optional)
     * @return a list of signature for each hash value of the documents to be signed
     */
    public List<String> signHash(String userId, String credentialID, List<String> hashes, String hashAlgorithmOID,
                                 String signAlgo, String signAlgoParams) throws Exception {
        Optional<Credentials> credentialsOptional = this.credentialsRepository.findById(credentialID);
        if(credentialsOptional.isEmpty()) {
            logger.error("No credential was found with the given identifier.");
            throw new Exception("No credential was found with the given identifier.");
        }

        Credentials credential = credentialsOptional.get();
        if(!credential.getUserID().equals(userId)){
            logger.error("The credential doesn't belong to the user.");
            throw new Exception("The credential doesn't belong to the user.");
        }

        if (!credential.getKeyAlgo().contains(signAlgo)){
            logger.error("The signature algorithm indicated is not supported by the signing key chosen.");
            throw new Exception("The signature algorithm indicated is not supported by the signing key chosen.");
        }

        String signatureAlgorithm;
        try {
            signatureAlgorithm = getSignatureAlgorithm(signAlgo, signAlgoParams, hashAlgorithmOID);
        }catch (Exception e){
            logger.error(e.getMessage());
            throw new Exception("An error occurred when trying to determine the signature algorithm to use.");
        }

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
    
    private String getSignatureAlgorithm(String signAlgo, String signAlgoParams, String hashAlgorithmOID) throws Exception {
        DefaultAlgorithmNameFinder algFinder = new DefaultAlgorithmNameFinder();
        ASN1ObjectIdentifier signAlgoOID = new ASN1ObjectIdentifier(signAlgo);

        try{
            SignatureAlgorithm signAlgorithm = SignatureAlgorithm.forOID(signAlgoOID.getId());
            String algorithmName = algFinder.getAlgorithmName(new ASN1ObjectIdentifier(signAlgorithm.getOid()));
            logger.info("The algorithm defined in the signAlgo parameter already contains an hash algorithm." +
                  " Algorithm Name found: {}", algorithmName);
            return algorithmName;
        }
        catch (IllegalArgumentException e){
            logger.error(e.getMessage());

            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forOID(signAlgo);
            logger.info("Found the encryption algorithm from the signAlgo OID: {}", encryptionAlgorithm.getName());

            DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(hashAlgorithmOID);
            logger.info("Found the digestion algorithm from the hashAlgorithm OID: {}", digestAlgorithm.getName());

            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
            String algorithmName = algFinder.getAlgorithmName(new ASN1ObjectIdentifier(signatureAlgorithm.getOid()));
            logger.info("From the signAlgo and the hashAlgorithmOID, the signature algorithm was obtained: {}",
                  algorithmName);
            return algorithmName;
        }
    }
}
