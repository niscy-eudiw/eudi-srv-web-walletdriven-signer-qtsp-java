package eu.europa.ec.eudi.signer.r3.resource_server.model.keys;

import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

/**
 * The component responsible for managing KeyPairs
 */
public class KeysService {

    private final HsmService hsmService;

    public KeysService(HsmService hsmService){
        this.hsmService = hsmService;
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
}
