/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import eu.europa.ec.eudi.signer.r3.resource_server.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.SecretKey;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.SecretKeyRepository;
import org.bouncycastle.asn1.DERSequenceGenerator;
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
    private final HsmInformation hsmInfo;
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
              new CKA(CKA.LABEL, "secret_key_wrapper"),
              new CKA(CKA.ID, "secret_key_wrapper"),
              new CKA(CKA.TOKEN, false),
              new CKA(CKA.SENSITIVE, false), // CK_TRUE if object is sensitive
              new CKA(CKA.WRAP, true), // CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)
              new CKA(CKA.UNWRAP, true), // CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys)
              new CKA(CKA.EXTRACTABLE, true)); // CK_TRUE if key is extractable and can be wrapped
        byte[] secret_key = CE.GetAttributeValue(session, secretKeyWrap, CKA.VALUE).getValue();
        this.secretKey = secret_key;

        CE.DestroyObject(session, secretKeyWrap);
        this.hsmInfo.releaseSession(sessionRef);
        return secret_key;
    }

    public void setSecretKey(byte[] secretKeyBytes) throws Exception {
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        CKA[] secretTempl = new CKA[]{
              new CKA(CKA.CLASS, CKO.SECRET_KEY),
              new CKA(CKA.KEY_TYPE, CKK.AES),
              new CKA(CKA.VALUE, secretKeyBytes),
              new CKA(CKA.LABEL, "secret_key_wrapper"),
              new CKA(CKA.ID, "secret_key_wrapper"),
              new CKA(CKA.TOKEN, false),
              new CKA(CKA.SENSITIVE, false),
              new CKA(CKA.WRAP, true),
              new CKA(CKA.UNWRAP, true),
              new CKA(CKA.EXTRACTABLE, true)
        };
        long obj = CE.CreateObject(session, secretTempl);
        this.secretKey = secretKeyBytes;

        CE.DestroyObject(session, obj);
        this.hsmInfo.releaseSession(sessionRef);
    }

    // loads the secret key from the bytes for the current session
    public long loadSecretKey(long session, byte[] secretKeyBytes) {
        CKA[] secretTempl = new CKA[]{
              new CKA(CKA.CLASS, CKO.SECRET_KEY),
              new CKA(CKA.KEY_TYPE, CKK.AES),
              new CKA(CKA.VALUE, secretKeyBytes),
              new CKA(CKA.LABEL, "secret_key_wrapper"),
              new CKA(CKA.ID, "secret_key_wrapper"),
              new CKA(CKA.TOKEN, false),
              new CKA(CKA.SENSITIVE, false),
              new CKA(CKA.WRAP, true),
              new CKA(CKA.UNWRAP, true),
              new CKA(CKA.EXTRACTABLE, true)
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

        CKA[] pubTemplate = new CKA[]{
              new CKA(CKA.MODULUS_BITS, keySize),
              new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
              new CKA(CKA.WRAP, true),
              new CKA(CKA.VERIFY, true),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.LABEL, "rsa-public-key"),
              new CKA(CKA.ID, "rsa-public-key-id")
        };

        CKA[] privTemplate = new CKA[]{
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.PRIVATE, true),
              new CKA(CKA.SENSITIVE, true),
              new CKA(CKA.SIGN, true),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.LABEL, "rsa-private-key"),
              new CKA(CKA.ID, "rsa-private-key-id"),
        };

        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTemplate, privTemplate, pubKey, privKey);
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
    public byte[][] generateECPrime256v1KeyPair() throws Exception {
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();
        long secretKeyObj = loadSecretKey(session, this.secretKey);

        // P-256 key (also known as secp256r1 or prime256v1), the oid 1.2.840.10045.3.1.7
        //   has DER encoding in Hex 06082a8648ce3d030107
        byte[] ecCurveParams = Hex.s2b("06082a8648ce3d030107");
        CKA[] pubTempl = new CKA[]{
              new CKA(CKA.EC_PARAMS, ecCurveParams),
              new CKA(CKA.VERIFY, true),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.LABEL, "P256-public-key"),
              new CKA(CKA.ID, "P256-public-key")
        };

        CKA[] privTempl = new CKA[]{
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.PRIVATE, true),
              new CKA(CKA.SENSITIVE, true),
              new CKA(CKA.SIGN, true),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.LABEL, "P256-private-key"),
              new CKA(CKA.ID, "P256-private-key"),
        };

        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);
        byte[][] keyPair = new byte[3][];
        keyPair[0] = CE.WrapKey(session, new CKM(CKM.AES_CBC), secretKeyObj, privKey.value());
        keyPair[1] = CE.GetAttributeValue(session, pubKey.value(), CKA.EC_POINT).getValue();
        keyPair[2] = CE.GetAttributeValue(session, pubKey.value(), CKA.EC_PARAMS).getValue();

        CE.DestroyObject(session, secretKeyObj);
        this.hsmInfo.releaseSession(sessionRef);
        return keyPair;
    }

    private long unwrapRSAKey(long session, long secretKey, byte[] wrappedKey) {
        CKA[] templateUnwrap = new CKA[]{
              new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
              new CKA(CKA.KEY_TYPE, CKK.RSA),
              new CKA(CKA.LABEL, "RSA-private-key-unwrapped"),
              new CKA(CKA.ID, "RSA-private-key-unwrapped"),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.SENSITIVE, true),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.SIGN, true),
        };
        return CE.UnwrapKey(session, new CKM(CKM.AES_CBC), secretKey, wrappedKey, templateUnwrap);
    }

    private long unwrapP256Key(long session, long secretKey, byte[] wrappedKey){
        CKA[] templateUnwrap = new CKA[]{
              new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
              new CKA(CKA.KEY_TYPE, CKK.EC),
              new CKA(CKA.LABEL, "P256-private-key-unwrapped"),
              new CKA(CKA.ID, "P256-private-key-unwrapped"),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.SENSITIVE, true),
              new CKA(CKA.EXTRACTABLE, true),
              new CKA(CKA.SIGN, true),
        };
        return CE.UnwrapKey(session, new CKM(CKM.AES_CBC), secretKey, wrappedKey, templateUnwrap);
    }

    /**
     * Function that allows to obtain a signature value of the DTBSR value with a RSA private key and given signature algorithm.
     *
     * @param wrappedPrivateKey  the previously wrapped RSA private key chosen
     * @param DTBSR              the value of the hash to be signed
     * @param signatureAlgorithm the signature algorithm to be used
     * @return the value of the signature
     */
    public byte[] signDTBSWithRSAAndGivenAlgorithm(byte[] wrappedPrivateKey, byte[] DTBSR, String signatureAlgorithm)
          throws Exception {
        // init session
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        long secretKeyObj = loadSecretKey(session, this.secretKey);

        // Unwrap private key
        long privateKey = unwrapRSAKey(session, secretKeyObj, wrappedPrivateKey);

        // Get Long value for signature
        long signatureAlgLong = determineLongValueForAlgorithm(signatureAlgorithm);

        // Sign bytes
        CE.SignInit(session, new CKM(signatureAlgLong), privateKey);
        byte[] signed = CE.Sign(session, DTBSR);

        CE.DestroyObject(session, secretKeyObj);
        this.hsmInfo.releaseSession(sessionRef);
        return signed;
    }

    public byte[] signDTBSWithRSAAndSHA256(byte[] wrappedPrivateKey, byte[] DTBSR) throws Exception {
        return signDTBSWithRSAAndGivenAlgorithm(wrappedPrivateKey, DTBSR, "SHA256WITHRSA");
    }

    /**
     * Function that allows to obtain a signature value of the DTBSR value with a ECDSA private key and given signature algorithm.
     *
     * @param wrappedPrivateKey  the previously wrapped ECDSA private key chosen
     * @param DTBSR              the value of the hash to be signed
     * @param signatureAlgorithm the signature algorithm to be used
     * @return the value of the signature
     */
    public byte[] signDTBSWithECDSAAndGivenAlgorithm(byte[] wrappedPrivateKey, byte[] DTBSR, String signatureAlgorithm)
          throws Exception {
        // init session
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        long secretKeyObj = loadSecretKey(session, this.secretKey);

        // Unwrap private key
        long privateKey = unwrapP256Key(session, secretKeyObj, wrappedPrivateKey);

        // Get Long value for signature
        long signatureAlgLong = determineLongValueForAlgorithm(signatureAlgorithm);

        // Sign bytes
        CE.SignInit(session, new CKM(signatureAlgLong), privateKey);
        byte[] signed = CE.Sign(session, DTBSR);

        CE.DestroyObject(session, secretKeyObj);
        this.hsmInfo.releaseSession(sessionRef);
        return DEREncodeECDSASignatureValue(signed);
    }

    public byte[] signDTBSWithECDSAAndSHA256(byte[] wrappedPrivateKey, byte[] DTBSR) throws Exception {
        return signDTBSWithECDSAAndGivenAlgorithm(wrappedPrivateKey, DTBSR, "SHA256WITHECDSA");
    }

    public void verifyRSASignature(byte[] DTBSR, byte[] signature, byte[] publicKey) throws Exception {
        // init session
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        // Get Public Key Parameters
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec pKeySpec = new X509EncodedKeySpec(publicKey);
        RSAPublicKey pk = (RSAPublicKey) keyFactory.generatePublic(pKeySpec);

        CKA[] pubTempl = new CKA[]{
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
        long publicKeyValue = CE.CreateObject(session, pubTempl);

        // Verify Signature
        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), publicKeyValue);
        CE.Verify(session, DTBSR, signature);

        this.hsmInfo.CloseSession(sessionRef);
    }

    public void verifyP256Signature(byte[] DTBSR, byte[] signature, byte[] ecPointBytes) throws Exception {
        // init session
        LongRef sessionRef = this.hsmInfo.getSession();
        long session = sessionRef.value();

        byte[] ecCurveParams = Hex.s2b("06082a8648ce3d030107");
        CKA[] pubTempl = new CKA[]{
              new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
              new CKA(CKA.KEY_TYPE, CKK.EC),
              new CKA(CKA.EC_PARAMS, ecCurveParams),
              new CKA(CKA.EC_POINT, ecPointBytes),
              new CKA(CKA.WRAP, true),
              new CKA(CKA.VERIFY, true),
              new CKA(CKA.TOKEN, true),
              new CKA(CKA.LABEL, "labelrsa-publicloaded"),
              new CKA(CKA.ID, "labelrsa-publicloaded")
        };
        long publicKeyValue = CE.CreateObject(session, pubTempl);

        // Verify Signature
        CE.VerifyInit(session, new CKM(CKM.ECDSA_SHA256), publicKeyValue);
        CE.Verify(session, DTBSR, signature);

        this.hsmInfo.CloseSession(sessionRef);
    }

    private long determineLongValueForAlgorithm(String signatureAlgorithm) throws Exception {
        return switch (signatureAlgorithm) {
            case "RSA" -> 1L;
            case "SHA256WITHRSA" -> 64L;
            case "SHA384WITHRSA" -> 65L;
            case "SHA512WITHRSA" -> 66L;

            case "ECDSA" -> 4161L;
            case "SHA256WITHECDSA"-> 4164L;
            case "SHA384WITHECDSA"->4165L;
            case "SHA512WITHECDSA" -> 4166L;

            default -> throw new Exception("The signature algorithm is not supported.");
        };
    }

    private byte[] DEREncodeECDSASignatureValue(byte[] signature) throws Exception{
        int len = signature.length / 2;
        byte[] r = Arrays.copyOfRange(signature, 0, len);
        BigInteger rInt = new BigInteger(1, r);
        byte[] s = Arrays.copyOfRange(signature, len, signature.length);
        BigInteger sInt = new BigInteger(1, s);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DERSequenceGenerator seq = new DERSequenceGenerator(baos);
        seq.addObject(new org.bouncycastle.asn1.ASN1Integer(rInt));
        seq.addObject(new org.bouncycastle.asn1.ASN1Integer(sInt));
        seq.close();
        return baos.toByteArray();
    }
}