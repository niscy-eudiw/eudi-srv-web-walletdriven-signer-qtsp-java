package eu.europa.ec.eudi.signer.r3.qtsp.model.keys;

import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.qtsp.model.keys.hsm.HsmService;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * The component responsible for managing KeyPairs
 */
public class KeysService {

    private HsmService hsmService;

    public KeysService(HsmService hsmService){
        this.hsmService = hsmService;
    }

    /**
     * Function that generates RSA key pair, and returns its values in an array.
     * The first position of the array contains the private key bytes.
     * The second position of the array contains the public key modulus bytes.
     * The third position of the array contains the public key public_exponent bytes.
     */
    public byte[][] RSAKeyPairGeneration() throws Exception{
        return this.hsmService.generateRSAKeyPair(1024);
    }

    public PublicKey getRSAPublicKeyFromSpecs(BigInteger modulus, BigInteger public_exponent) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pKeySpec = new RSAPublicKeySpec(modulus, public_exponent);
        return keyFactory.generatePublic(pKeySpec);
    }

    private static KeyPair keyPairGeneration() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private void EdDSAKeyPairGeneration() throws Exception {

        byte[][] keyPair = this.hsmService.generateEdDSAKeyPair(); // curve edwards 25519
        byte[] privKey = keyPair[0];
        byte[] publKey = keyPair[1];

        /*KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec();
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        System.out.println(publicKey.getAlgorithm());*/

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPairLocal = keyPairGenerator.generateKeyPair();
        System.out.println(keyPairLocal.getPublic().getAlgorithm());

        System.out.println("HSM: "+ publKey.length);
        System.out.println("Local: "+ keyPairLocal.getPublic().getEncoded().length);
    }
}
