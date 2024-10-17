package eu.europa.ec.eudi.signer.r3.resource_server.model.keys;

import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

/**
 * The component responsible for managing KeyPairs
 */
public class KeysService {

    private final HsmService hsmService;

    public KeysService(HsmService hsmService){
        this.hsmService = hsmService;
    }

    public KeyPairRegister RSAKeyPairGeneration() throws Exception{
        byte[][] keyPairBytes = this.hsmService.generateRSAKeyPair(2048);
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

    public KeyPairRegister EdDSAKeyPairGeneration() throws Exception{
        byte[][] keyPairBytes = this.hsmService.generateEdDSAKeyPair();

        byte[] privateKeyBytes = keyPairBytes[0];
        byte[] publicKeyBytes = keyPairBytes[1];

        KeyPairRegister keyPair = new KeyPairRegister();
        keyPair.setPrivateKeyBytes(privateKeyBytes);
        PublicKey EdDSAPublicKey = getEdDSAPublicKeyFromBytes(publicKeyBytes);
        keyPair.setPublicKeyValue(EdDSAPublicKey);
        return keyPair;
    }

    private PublicKey getEdDSAPublicKeyFromBytes(byte[] EdDSAPublicKeyBytes) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECParameterSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point = ECPointUtil.decodePoint(params.getCurve(), EdDSAPublicKeyBytes);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, params);
        return keyFactory.generatePublic(publicKeySpec);
    }
}
