package eu.europa.ec.eudi.signer.r3.resource_server.unit.certificates;

import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.CertificatesService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.KeyPairRegister;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("unit")
public class CertificatesServiceTests {

	@Autowired
	private EjbcaService ejbcaService;

	@Autowired
	private HsmService hsmService;

	private CertificatesService certificatesService;

	@BeforeEach
	public void setup() {
		certificatesService = new CertificatesService(hsmService, ejbcaService);
	}

	@Test
	void testBase64EncodeDecodeCertificate_shouldReturnSameCertificate() throws Exception {
		// Arrange
		X509Certificate original = generateSelfSignedCertificate();

		// Act
		String encoded = this.certificatesService.base64EncodeCertificate(original);
		X509Certificate decoded = this.certificatesService.base64DecodeCertificate(encoded);

		// Assert
		assertEquals(original, decoded);
	}

	private X509Certificate generateSelfSignedCertificate() throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(1024, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		X500Name dnName = new X500Name("CN=John Doe");
		BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis());

		Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24);
		Date notAfter = new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));

		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, notBefore, notAfter, dnName, keyPair.getPublic());

		BasicConstraints basicConstraints = new BasicConstraints(true);
		certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));
	}

	@Test
	void testBase64EncodeCertificate_nullCertificate_shouldThrowException() {
		assertThrows(NullPointerException.class, () -> {
			this.certificatesService.base64EncodeCertificate(null);
		});
	}

	@Test
	void testBase64DecodeCertificate_invalidBase64_shouldThrowException() {
		assertThrows(Exception.class, () -> {
			this.certificatesService.base64DecodeCertificate("THIS_IS_NOT_BASE64");
		});
	}

	@Test
	void testGenerateP256Certificates_shouldReturnCertificate() throws Exception {
		String givenName = "John";
		String surname = "Doe";
		String subjectCN = givenName+" "+surname;
		String countryCode = "UT";

		KeyPairRegister keyPair = create_aux_p256_keypair();

		List<X509Certificate> chain = this.certificatesService.generateP256Certificates(
			  keyPair.getPublicKeyValue(), givenName, surname, subjectCN,
			  countryCode, keyPair.getPrivateKeyBytes());
		assertNotNull(chain);
		assertFalse(chain.isEmpty());
		assertInstanceOf(X509Certificate.class, chain.get(0));
	}

	@Test
	void testGenerateP256Certificates_withSpaces_shouldReturnCertificate() throws Exception {
		String givenName = "John ";
		String surname = "Doe  ";
		String subjectCN = givenName+" "+surname;
		String countryCode = "UT";

		KeyPairRegister keyPair = create_aux_p256_keypair();

		List<X509Certificate> chain = this.certificatesService.generateP256Certificates(
			  keyPair.getPublicKeyValue(), givenName, surname, subjectCN,
			  countryCode, keyPair.getPrivateKeyBytes());
		assertNotNull(chain);
		assertFalse(chain.isEmpty());
		assertInstanceOf(X509Certificate.class, chain.get(0));
	}

	@Test
	void testGenerateP256Certificates_withSpecialChars_shouldReturnCertificate() throws Exception {
		// special chars: . , - _ @ / ( ) ' : + = " \
		// < > # ;

		String givenName = "John.,-_@/()':<>";
		String surname = "Doe+=#;\"\\";
		String subjectCN = givenName+" "+surname;
		String countryCode = "UT";

		KeyPairRegister keyPair = create_aux_p256_keypair();

		List<X509Certificate> chain = this.certificatesService.generateP256Certificates(
			  keyPair.getPublicKeyValue(), givenName, surname, subjectCN,
			  countryCode, keyPair.getPrivateKeyBytes());
		assertNotNull(chain);
		assertFalse(chain.isEmpty());
		assertInstanceOf(X509Certificate.class, chain.get(0));
	}

	@Test
	void testGenerateP256Certificates_withMultipleNames_shouldReturnCertificate() throws Exception {
		String givenName = "Mr John";
		String surname = "Doe";
		String subjectCN = givenName+" "+surname;
		String countryCode = "UT";

		KeyPairRegister keyPair = create_aux_p256_keypair();

		List<X509Certificate> chain = this.certificatesService.generateP256Certificates(
			  keyPair.getPublicKeyValue(), givenName, surname, subjectCN,
			  countryCode, keyPair.getPrivateKeyBytes());
		assertNotNull(chain);
		assertFalse(chain.isEmpty());
		assertInstanceOf(X509Certificate.class, chain.get(0));
	}

	@Test
	void testGenerateRSACertificates_shouldReturnCertificate() throws Exception {
		String givenName = "John";
		String surname = "Doe";
		String subjectCN = givenName+" "+surname;
		String countryCode = "UT";

		KeyPairRegister keyPair = create_aux_rsa_keypair();

		List<X509Certificate> chain = this.certificatesService.generateRSACertificates(
			  keyPair.getPublicKeyValue(), givenName, surname, subjectCN,
			  countryCode, keyPair.getPrivateKeyBytes());
		assertNotNull(chain);
		assertFalse(chain.isEmpty());
		assertInstanceOf(X509Certificate.class, chain.get(0));
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

	private PublicKey getRSAPublicKeyFromSpecs(BigInteger modulus, BigInteger public_exponent) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pKeySpec = new RSAPublicKeySpec(modulus, public_exponent);
		return keyFactory.generatePublic(pKeySpec);
	}

	private KeyPairRegister create_aux_p256_keypair() throws Exception {
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

	private KeyPairRegister create_aux_rsa_keypair() throws Exception {
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
}
