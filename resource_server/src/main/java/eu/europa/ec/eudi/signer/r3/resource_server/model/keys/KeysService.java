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

package eu.europa.ec.eudi.signer.r3.resource_server.model.keys;

import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.SecretKey;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.SecretKeyRepository;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.List;

/**
 * The component responsible for managing KeyPairs
 */
public class KeysService implements IKeysService{
    private final HsmService hsmService;
    private static final int IVLENGTH = 12;

    public KeysService(HsmService hsmService, SecretKeyRepository secretKeyRepositoryLoaded, EncryptionHelper encryptionHelper) throws Exception {
        this.hsmService = hsmService;

        List<SecretKey> secretKeys = secretKeyRepositoryLoaded.findAll();
        if (secretKeys.isEmpty()) {
            // generates a secret key to wrap the private keys from the HSM
            byte[] secretKeyBytes = this.hsmService.initSecretKey();
            byte[] iv = encryptionHelper.genInitializationVector(IVLENGTH);

            // encrypts the secret key before saving it in the db
            byte[] encryptedSecretKeyBytes = encryptionHelper.encrypt("AES/GCM/NoPadding", iv, secretKeyBytes);

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedSecretKeyBytes.length);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedSecretKeyBytes);

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
            byte[] encryptedSecretKey = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedSecretKey);

            // decrypts the secret key
            byte[] secretKeyBytes = encryptionHelper.decrypt("AES/GCM/NoPadding", iv, encryptedSecretKey);

            // loads the decrypted key to the HSM
            this.hsmService.setSecretKey(secretKeyBytes);
        }

    }

    public KeyPairRegister generateRSAKeyPair(int keySizeInBits) throws Exception{
        byte[][] keyPairBytes = this.hsmService.generateRSAKeyPair(keySizeInBits);
        KeyPairRegister keyPair = new KeyPairRegister();
        keyPair.setPrivateKeyBytes(keyPairBytes[0]);

        byte[] modulus = keyPairBytes[1];
        BigInteger ModulusBI = new BigInteger(1, modulus);
        byte[] public_exponent = keyPairBytes[2];
        BigInteger PublicExponentBI = new BigInteger(1, public_exponent);
        keyPair.setPublicKeyValue(getRSAPublicKeyFromSpecs(ModulusBI, PublicExponentBI));

        return keyPair;
    }

    private PublicKey getRSAPublicKeyFromSpecs(BigInteger modulus, BigInteger public_exponent) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pKeySpec = new RSAPublicKeySpec(modulus, public_exponent);
        return keyFactory.generatePublic(pKeySpec);
    }

    public byte[] signDTBSWithRSAAndGivenAlgorithm (byte[] wrappedPrivateKey, byte[] DTBSR, String signatureAlgorithm) throws Exception{
        return hsmService.signDTBSWithRSAAndGivenAlgorithm(wrappedPrivateKey, DTBSR, signatureAlgorithm);
    }

    public KeyPairRegister generateP256KeyPair() throws Exception{
        byte[][] keyPairBytes = this.hsmService.generateECPrime256v1KeyPair();

        byte[] privateKeyBytes = keyPairBytes[0];
        byte[] publicKeyQPoint = keyPairBytes[1];
        byte[] publicKeyParams = keyPairBytes[2];

        KeyPairRegister keyPair = new KeyPairRegister();
        keyPair.setPrivateKeyBytes(privateKeyBytes);
        PublicKey EdDSAPublicKey = getECPublicKeyFromSpecs(publicKeyQPoint, publicKeyParams);
        keyPair.setPublicKeyValue(EdDSAPublicKey);
        return keyPair;
    }

    private ECPublicKey getECPublicKeyFromSpecs(byte[] publicKeyQPoint, byte[] publicKeyParams) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(publicKeyParams);
        final org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(oid.getId());
        final java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(ecSpec.getCurve(), ecSpec.getSeed());
        final java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve, ASN1OctetString.getInstance(publicKeyQPoint).getOctets());
        final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(ecSpec.getCurve(), ecPoint);
        final org.bouncycastle.jce.spec.ECPublicKeySpec pubKeySpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(ecp, ecSpec);
        final KeyFactory keyfactory = KeyFactory.getInstance("ECDSA", "BC");
		return (ECPublicKey) keyfactory.generatePublic(pubKeySpec);
    }

    public byte[] getQPointBytesFromECPublicKey(ECPublicKey ECPublicKey) throws Exception{
        // the value of the q point
        ECPoint w = ECPublicKey.getW();

        byte[] x = w.getAffineX().toByteArray();
        byte[] y = w.getAffineY().toByteArray();
        int fieldSizeBytes = (ECPublicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        x = padToFieldSize(x, fieldSizeBytes);
        y = padToFieldSize(y, fieldSizeBytes);

        // Encode the point in uncompressed format: 0x04 + x + y
        byte[] qPointBytes = new byte[1 + x.length + y.length];
        qPointBytes[0] = 0x04; // Uncompressed point indicator
        System.arraycopy(x, 0, qPointBytes, 1, x.length);
        System.arraycopy(y, 0, qPointBytes, 1 + x.length, y.length);

		return (new DEROctetString(qPointBytes)).getEncoded();
    }

    private static byte[] padToFieldSize(byte[] coord, int fieldSize) {
        if (coord.length == fieldSize) {
            return coord;
        }
        byte[] paddedCoord = new byte[fieldSize];
        System.arraycopy(coord, Math.max(0, coord.length - fieldSize), paddedCoord, Math.max(0, fieldSize - coord.length), Math.min(coord.length, fieldSize));
        return paddedCoord;
    }

    public byte[] signDTBSWithECDSAAndGivenAlgorithm(byte[] wrappedPrivateKey, byte[] DTBSR, String signatureAlgorithm) throws Exception{
        return hsmService.signDTBSWithECDSAAndGivenAlgorithm(wrappedPrivateKey, DTBSR, signatureAlgorithm);
    }

}
