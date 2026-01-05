package eu.europa.ec.eudi.signer.r3.resource_server.model.keys;

public interface IKeysService {
	KeyPairRegister generateRSAKeyPair(int keySizeInBits) throws Exception;
	KeyPairRegister generateP256KeyPair() throws Exception;
	byte[] signDTBSWithRSAAndGivenAlgorithm(byte[] wrappedPrivateKey, byte[] DTBSR, String signatureAlgorithm) throws Exception;
	byte[] signDTBSWithECDSAAndGivenAlgorithm(byte[] wrappedPrivateKey, byte[] DTBSR, String signatureAlgorithm) throws Exception;
}
