package eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import eu.europa.ec.eudi.signer.r3.resource_server.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.SecretKey;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.SecretKeyRepository;
import org.pkcs11.jacknji11.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

@Component
public class HsmService {

    private byte[] secretKey;
    private HsmInformation hsmInfo;
    private static final int IVLENGTH = 12;

    public HsmService(
          @Autowired SecretKeyRepository secretKeyRepositoryLoaded,
          @Autowired AuthConfig authProperties
    ) throws Exception {

        // Load test_slot from global variable
        long slot = 0;
        String testSlotEnv = System.getenv("JACKNJI11_TEST_TESTSLOT");
        if (testSlotEnv != null && !testSlotEnv.isEmpty()) {
            slot = Long.parseLong(testSlotEnv);
        }

        // Load user_pin from global variable
        byte[] pin = "userpin".getBytes();
        String userPinEnv = System.getenv("JACKNJI11_TEST_USER_PIN");
        if (userPinEnv != null && !userPinEnv.isEmpty()) {
            pin = userPinEnv.getBytes();
        }

        this.hsmInfo = new HsmInformation(slot, pin);
        CE.Initialize();

        char[] passphrase = authProperties.getDbEncryptionPassphrase().toCharArray();
        byte[] saltBytes = Base64.getDecoder().decode(authProperties.getDbEncryptionSalt());
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec encryptionKeySpec = new PBEKeySpec(passphrase, saltBytes, 65536, 256);
        Key encryptionKey = new SecretKeySpec(factory.generateSecret(encryptionKeySpec).getEncoded(), "AES");

        // init Secret Key or loads it from the database
        List<SecretKey> secretKeys = secretKeyRepositoryLoaded.findAll();
        if (secretKeys.isEmpty()) {
            // generates a secret key to wrap the private keys from the HSM
            byte[] secretKeyBytes = initSecretKey();

            byte[] iv = new byte[IVLENGTH];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            // encrypts the secret key before saving it in the db
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec algSpec = new GCMParameterSpec(128, iv);
            c.init(Cipher.ENCRYPT_MODE, encryptionKey, algSpec);
            byte[] encryptedSecretKeyBytes = c.doFinal(secretKeyBytes);

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedSecretKeyBytes.length);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedSecretKeyBytes);

            SecretKey secretKey = new SecretKey(byteBuffer.array());
            secretKeyRepositoryLoaded.save(secretKey);
        } else {
            SecretKey sk = secretKeys.get(0);
            byte[] encryptedSecretKeyBytes = sk.getSecretKey();

            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedSecretKeyBytes);
            byte[] iv = new byte[IVLENGTH];
            byteBuffer.get(iv);
            byte[] encryptedSecretKey = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedSecretKey);

            // decrypts the secret key
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec algSpec = new GCMParameterSpec(128, iv);
            c.init(Cipher.DECRYPT_MODE, encryptionKey, algSpec);
            byte[] secretKeyBytes = c.doFinal(encryptedSecretKey);

            setSecretKey(secretKeyBytes);
        }
    }

    // Creates a new Secret Key that will be use for the operation of wrap and
    // unwrap:
    public byte[] initSecretKey() throws Exception {
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        long secretKeyWrap = CE.GenerateKey(session, new CKM(CKM.AES_KEY_GEN),
              new CKA(CKA.VALUE_LEN, 32),
              new CKA(CKA.LABEL, "wrapKey"),
              new CKA(CKA.ID, "wrapKey"),
              new CKA(CKA.TOKEN, false),
              new CKA(CKA.SENSITIVE, false),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.DERIVE, true));
        byte[] secret_key = CE.GetAttributeValue(session, secretKeyWrap, CKA.VALUE).getValue();
        this.secretKey = secret_key;

        CE.DestroyObject(session, secretKeyWrap);
        this.hsmInfo.releaseSession(sessionRef);
        return secret_key;
    }

    public void setSecretKey(byte[] secretKeyBytes) throws Exception {
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        CKA[] secretTempl = new CKA[] {
              new CKA(CKA.CLASS, CKO.SECRET_KEY),
              new CKA(CKA.KEY_TYPE, CKK.AES),
              new CKA(CKA.VALUE, secretKeyBytes),
              new CKA(CKA.LABEL, "wrapKey"),
              new CKA(CKA.ID, "wrapKey"),
              new CKA(CKA.TOKEN, false),
              new CKA(CKA.SENSITIVE, false),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.DERIVE, true)
        };
        long obj = CE.CreateObject(session, secretTempl);
        this.secretKey = secretKeyBytes;

        CE.DestroyObject(session, obj);
        this.hsmInfo.releaseSession(sessionRef);
    }

    // loads the secret key from the bytes for the current session
    public long loadSecretKey(long session, byte[] secretKeyBytes) throws Exception {
        CKA[] secretTempl = new CKA[] {
              new CKA(CKA.CLASS, CKO.SECRET_KEY),
              new CKA(CKA.KEY_TYPE, CKK.AES),
              new CKA(CKA.VALUE, secretKeyBytes),
              new CKA(CKA.LABEL, "wrapKey"),
              new CKA(CKA.ID, "wrapKey"),
              new CKA(CKA.TOKEN, false),
              new CKA(CKA.SENSITIVE, false),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.DERIVE, true)
        };
        return CE.CreateObject(session, secretTempl);
    }

    /**
     * Function that generates a RSA key pair, and returns its ref in an array.
     * The first position of the array contains the private key bytes.
     * The second position of the array contains the public key modulus bytes.
     * The third position of the array contains the public key public_exponent
     * bytes.
     */
    public byte[][] generateRSAKeyPair(int keySize) throws Exception {
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();
        long secretKeyObj = loadSecretKey(session, this.secretKey);

        CKA[] pubTempl = new CKA[] {
              new CKA(CKA.MODULUS_BITS, keySize),
              new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
              new CKA(CKA.WRAP, true),
              new CKA(CKA.VERIFY, true),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.LABEL, "rsa-public-key"),
              new CKA(CKA.ID, "rsa-public-key-id")
        };

        CKA[] privTempl = new CKA[] {
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.PRIVATE, true),
              new CKA(CKA.SENSITIVE, true),
              new CKA(CKA.SIGN, true),
              new CKA(CKA.UNWRAP, true),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.LABEL, "rsa-private-key"),
              new CKA(CKA.ID, "rsa-private-key-id"),
        };

        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);
        byte[][] keyPair = new byte[3][];
        keyPair[0] = CE.WrapKey(session, new CKM(CKM.AES_CBC), secretKeyObj, privKey.value());
        keyPair[1] = CE.GetAttributeValue(session, pubKey.value(), CKA.MODULUS).getValue();
        keyPair[2] = CE.GetAttributeValue(session, pubKey.value(), CKA.PUBLIC_EXPONENT).getValue();

        CE.DestroyObject(session, secretKeyObj);
        this.hsmInfo.releaseSession(sessionRef);
        return keyPair;
    }

    /**
     * Function that generates a EdDSA key pair, and returns its ref in an array.
     * The first position of the array contains the private key bytes.
     * The second position of the array contains the public key bytes.
     */
    public byte[][] generateEdDSAKeyPair() throws Exception {
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();
        long secretKeyObj = loadSecretKey(session, this.secretKey);

        CKA[] pubTempl = new CKA[] {
              new CKA(CKA.EC_PARAMS, "edwards25519"),
              new CKA(CKA.WRAP, true),
              new CKA(CKA.VERIFY, true),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.LABEL, "EdDSA-public-key"),
              new CKA(CKA.ID, "EdDSA-public-key")
        };

        CKA[] privTempl = new CKA[] {
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.PRIVATE, true),
              new CKA(CKA.SENSITIVE, true),
              new CKA(CKA.SIGN, true),
              new CKA(CKA.UNWRAP, true),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.LABEL, "EdDSA-private-key"),
              new CKA(CKA.ID, "EdDSA-private-key"),
        };

        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.EC_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);
        byte[][] keyPair = new byte[2][];
        keyPair[0] = CE.WrapKey(session, new CKM(CKM.AES_CBC), secretKeyObj, privKey.value());
        keyPair[1] = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE).getValue();

        CE.DestroyObject(session, secretKeyObj);
        this.hsmInfo.releaseSession(sessionRef);
        return keyPair;
    }

    public long UnwrapKey(long session, long secretKey, byte[] wrappedKey) {

        CKA[] secTemplUnwrap = new CKA[] {
              new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
              new CKA(CKA.KEY_TYPE, CKK.RSA),
              new CKA(CKA.LABEL, "privatekeyunwrapped"),
              new CKA(CKA.ID, "privatekeyunwrapped"),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.SENSITIVE, true),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.SIGN, true),
        };
        return CE.UnwrapKey(session, new CKM(CKM.AES_CBC), secretKey, wrappedKey, secTemplUnwrap);
    }

    public byte[] signDTBSwithRSAPKCS11(byte[] wrappedPrivateKey, byte[] DTBSR) throws Exception {
        // init session
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        long secretKeyObj = loadSecretKey(session, this.secretKey);

        // Unwrap private key
        long privateKey = UnwrapKey(session, secretKeyObj, wrappedPrivateKey);

        // Sign bytes
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privateKey);
        byte[] signed = CE.Sign(session, DTBSR);

        CE.DestroyObject(session, secretKeyObj);
        this.hsmInfo.releaseSession(sessionRef);
        return signed;
    }

    public byte[] signWithSomeAlgorithm(byte[] wrappedPrivateKey, byte[] DTBSR, String signatureAlgorithm) throws Exception {
        // init session
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        long secretKeyObj = loadSecretKey(session, this.secretKey);

        // Unwrap private key
        long privateKey = UnwrapKey(session, secretKeyObj, wrappedPrivateKey);
        // Get Long value for signature
        long signatureAlgLong = determineLongValueForAlgorithm(signatureAlgorithm);

        // Sign bytes
        CE.SignInit(session, new CKM(signatureAlgLong), privateKey);
        byte[] signed = CE.Sign(session, DTBSR);

        CE.DestroyObject(session, secretKeyObj);
        this.hsmInfo.releaseSession(sessionRef);
        return signed;
    }

    public long SetAttributePublicKey(long session, byte[] publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec pKeySpec = new X509EncodedKeySpec(publicKey);
        RSAPublicKey pk = (RSAPublicKey) keyFactory.generatePublic(pKeySpec);

        CKA[] pubTempl = new CKA[] {
              new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
              new CKA(CKA.KEY_TYPE, CKK.RSA),
              new CKA(CKA.MODULUS, pk.getModulus().toByteArray()),
              new CKA(CKA.PUBLIC_EXPONENT, pk.getModulus().toByteArray()),
              new CKA(CKA.WRAP, true),
              new CKA(CKA.VERIFY, true),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.LABEL, "labelrsa-publicloaded"),
              new CKA(CKA.ID, "labelrsa-publicloaded")
        };
        return CE.CreateObject(session, pubTempl);
    }

    public void VerifySignature(byte[] DTBSR, byte[] signature, byte[] publicKey) throws Exception {
        // init session
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        // Get Public Key Parameters
        long publicKeyValue = 0;
        publicKeyValue = SetAttributePublicKey(session, publicKey);

        // Verify Signature
        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), publicKeyValue);
        CE.Verify(session, DTBSR, signature);

        this.hsmInfo.CloseSession(sessionRef);
    }


    public long determineLongValueForAlgorithm(String signatureAlgorithm){
        if(signatureAlgorithm.equals("SHA256WITHRSA"))
            return 64L;
        if(signatureAlgorithm.equals("SHA384WITHRSA"))
            return 65L;
        if(signatureAlgorithm.equals("SHA512WITHRSA"))
            return 66L;
        else return 64L;
    }

}