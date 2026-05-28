package eu.europa.ec.eudi.signer.r3.resource_server.model.certificates;

import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class CertificatesServiceTests {
	@Mock
	private EjbcaService ejbcaService;
	@Mock
	private HsmService hsmService;
	@InjectMocks
	private CertificatesService certificatesService = new CertificatesService(hsmService, ejbcaService);;

	@Test
	void testBase64EncodeDecodeCertificate_shouldReturnSameCertificate() throws Exception {
		X509Certificate original = generateSelfSignedCertificate();

		String encoded = this.certificatesService.base64EncodeCertificate(original);
		X509Certificate decoded = this.certificatesService.base64DecodeCertificate(encoded);

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
	void testRemoveSemicolon() {
		String input = "John;  Doe,O=Test;";
		String expected = "John-  Doe,O=Test-";
		assertEquals(expected, CertificatesService.removeSemicolon(input));
	}

	@Test
	void testEscapeString() {
		// special chars: . , - _ @ / ( ) ' : + = " \
		// < > # ;

		String input = "John.,-_@/()':<> Doe+=#;\"\\";
		String expected = "John.\\,-_@/()':\\<\\> Doe\\+\\=#-\\\"\\\\";
		assertEquals(expected, CertificatesService.escapeString(input));
	}
}