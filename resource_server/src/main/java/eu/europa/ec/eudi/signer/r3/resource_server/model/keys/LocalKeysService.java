package eu.europa.ec.eudi.signer.r3.resource_server.model.keys;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.SecretKey;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.SecretKeyRepository;

public class LocalKeysService implements IKeysService {

    private static final Logger logger = LoggerFactory.getLogger(LocalKeysService.class);
    private final EncryptionHelper encryptionHelper;
    private static final int IVLENGTH = 12;
    private javax.crypto.SecretKey skEncryptionKey;
    private final byte[] skEncryptionIV;
    private static final String DEFAULT_TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public LocalKeysService(EncryptionHelper encryptionHelper, SecretKeyRepository secretKeyRepositoryLoaded) throws Exception {
        this.encryptionHelper = encryptionHelper;

        List<SecretKey> secretKeys = secretKeyRepositoryLoaded.findAll();
        int encryptionIvLength = 16;
        if (secretKeys.isEmpty()) {
            this.skEncryptionIV = encryptionHelper.genInitializationVector(encryptionIvLength);

            // generates a secret key to wrap the private keys from the HSM
            byte[] secretKeyBytes = initSecretKey();
            byte[] iv = encryptionHelper.genInitializationVector(IVLENGTH);

            byte[] encryptedSecretKeyBytes = encryptionHelper.encrypt("AES/GCM/NoPadding", iv, secretKeyBytes);

            ByteBuffer byteBuffer = ByteBuffer.allocate(IVLENGTH + encryptedSecretKeyBytes.length + encryptionIvLength);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedSecretKeyBytes);
            byteBuffer.put(this.skEncryptionIV);

            // saves in the db
            SecretKey sk = new SecretKey(byteBuffer.array());
            secretKeyRepositoryLoaded.save(sk);
        } else {
            // loads the encrypted key from the database
            SecretKey sk = secretKeys.get(0);
            byte[] encryptedSecretKeyBytes = sk.getSecretKey();

            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedSecretKeyBytes);
            byte[] iv = new byte[IVLENGTH];
            byteBuffer.get(iv);
            byte[] encryptedSecretKey = new byte[byteBuffer.remaining() - encryptionIvLength];
            byteBuffer.get(encryptedSecretKey);
            this.skEncryptionIV = new byte[encryptionIvLength];
            byteBuffer.get(this.skEncryptionIV);

            // decrypts the secret key
            byte[] secretKeyBytes = encryptionHelper.decrypt("AES/GCM/NoPadding", iv, encryptedSecretKey);

            // loads the decrypted key to the HSM
            setSkEncryptionKey(secretKeyBytes);
        }
    }

    private byte[] initSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        javax.crypto.SecretKey secretKey = keyGen.generateKey();
        this.skEncryptionKey = secretKey;
        logger.info("Generated secret key to encrypt private keys.");
        return secretKey.getEncoded();
    }

    private void setSkEncryptionKey(byte[] skEncryptionKey) {
        this.skEncryptionKey = new SecretKeySpec(skEncryptionKey, "AES");
        logger.info("Loaded secret key to encrypt private keys.");
    }

    @Override
    public KeyPairRegister generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        KeyPair pair = generator.generateKeyPair();
        byte[] encryptedPrivateKey = encryptionHelper.encrypt(DEFAULT_TRANSFORMATION, this.skEncryptionKey, this.skEncryptionIV, pair.getPrivate().getEncoded());
        logger.info("Generated new RSA signing keys locally.");
        return new KeyPairRegister(encryptedPrivateKey, pair.getPublic());
    }

    @Override
    public byte[] signDTBSWithRSAAndGivenAlgorithm(byte[] encodedPrivateKey, byte[] data, String signatureAlgorithm) throws Exception {
        byte[] privateKeyBytes = encryptionHelper.decrypt(DEFAULT_TRANSFORMATION, this.skEncryptionKey, this.skEncryptionIV, encodedPrivateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(privateKey);
        signer.update(data); // input data to be signed
        logger.info("Signed with RSA signing keys locally.");
        return signer.sign();
    }

    @Override
    public KeyPairRegister generateP256KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec("P-256"));
        KeyPair pair = generator.generateKeyPair();
        byte[] encryptedPrivateKey = encryptionHelper.encrypt(DEFAULT_TRANSFORMATION, this.skEncryptionKey, this.skEncryptionIV, pair.getPrivate().getEncoded());
        logger.info("Generated new P256 signing keys locally.");
        return new KeyPairRegister(encryptedPrivateKey, pair.getPublic());
    }

    @Override
    public byte[] signDTBSWithECDSAAndGivenAlgorithm(byte[] encodedPrivateKey, byte[] data, String signatureAlgorithm) throws Exception {
        byte[] privateKeyBytes = encryptionHelper.decrypt(DEFAULT_TRANSFORMATION, this.skEncryptionKey, this.skEncryptionIV, encodedPrivateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        PrivateKey privateKey = kf.generatePrivate(spec);

        if (signatureAlgorithm.equals("ECDSA")) {
            signatureAlgorithm = "NONEwithECDSA";
        } else if (signatureAlgorithm.equals("RSA")) {
            signatureAlgorithm = "NONEwithRSA";
        }

        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(privateKey);
        signer.update(data); // input data to be signed
        logger.info("Signed with P256 signing keys locally.");
        return signer.sign();
    }
}
