package eu.europa.ec.eudi.signer.r3.qtsp.model.certificates;

import eu.europa.ec.eudi.signer.r3.qtsp.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.qtsp.model.keys.hsm.HsmService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/***
 * The module response for managing certificates and certificate chains
 */
public class CertificatesService {

    private HsmService hsmService;
    private EjbcaService ejbcaService;

    public CertificatesService(HsmService hsmService, EjbcaService ejbcaService){
        this.hsmService = hsmService;
        this.ejbcaService = ejbcaService;
    }

    public String certificateToString(X509Certificate certificate) throws IOException {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(certificate);
            pemWriter.flush();
            return sw.toString();
        }
    }

    public String base64EncodeCertificate(X509Certificate certificate) throws Exception{
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    public X509Certificate stringToCertificate(String certificateString) throws IOException, CertificateException {
        try (StringReader stringReader = new StringReader(certificateString);
             PEMParser pemParser = new PEMParser(stringReader)) {
            Object object = pemParser.readObject();
            return new JcaX509CertificateConverter()
                  .getCertificate((X509CertificateHolder) object);
        }
    }

    public X509Certificate base64DecodeCertificate(String certificate) throws Exception{
        byte[] certificateBytes = Base64.getDecoder().decode(certificate);
        ByteArrayInputStream inputStream  =  new ByteArrayInputStream(certificateBytes);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)certFactory.generateCertificate(inputStream);
    }

    public List<X509Certificate> generateCertificates(PublicKey publicKey, String givenName, String surname, String subjectCN, String countryCode, byte[] privKeyValues) throws Exception {
        // Create a certificate Signing Request for the keys
        byte[] csrInfo = generateCertificateRequestInfo(publicKey, givenName, surname, subjectCN, countryCode, "Trust Provider Signer EUDIW");
        byte[] signature = hsmService.signDTBSwithRSAPKCS11(privKeyValues, csrInfo);
        PKCS10CertificationRequest certificateHSM = generateCertificateRequest(csrInfo, signature);
        String certificateString = "-----BEGIN CERTIFICATE REQUEST-----\n" + new String(Base64.getEncoder().encode(certificateHSM.getEncoded())) + "\n" + "-----END CERTIFICATE REQUEST-----";

        // Makes a request to the CA
        List<X509Certificate> certificateAndCertificateChain = this.ejbcaService.certificateRequest(certificateString, countryCode);
        if(!validateCertificateFromCA(certificateAndCertificateChain, givenName, surname, subjectCN, countryCode)){
            throw new Exception("Certificates received from CA are not valid");
        }
        return certificateAndCertificateChain;
    }

    private byte[] generateCertificateRequestInfo(PublicKey publicKey, String givenName, String surname, String commonName, String countryName, String organizationName)
          throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        final X500Name subjectDN = new X500NameBuilder(BCStyle.INSTANCE)
              .addRDN(BCStyle.CN, commonName)
              .addRDN(BCStyle.SURNAME, surname)
              .addRDN(BCStyle.GIVENNAME, givenName)
              .addRDN(BCStyle.C, countryName)
              .addRDN(BCStyle.O, organizationName)
              .build();

        ASN1Set attributes = new DERSet();

        // CertificationRequestInfo cri = new CertificationRequestInfo(subjectDN, pki, attributes);
        CertificationRequestInfo cri = new CertificationRequestInfo(subjectDN, pki, attributes);
        return cri.getEncoded();
    }

    private PKCS10CertificationRequest generateCertificateRequest(byte[] certificateRequestInfo, byte[] signature) {
        CertificationRequestInfo cri = CertificationRequestInfo.getInstance(certificateRequestInfo);
        DERBitString sig = new DERBitString(signature);

        AlgorithmIdentifier rsaWithSha256 = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        CertificationRequest cr = new CertificationRequest(cri, rsaWithSha256, sig);
        return new PKCS10CertificationRequest(cr);
    }

    private boolean validateCertificateFromCA(List<X509Certificate> certificatesAndCertificateChain, String givenName, String surname, String subjectCN, String countryCode){
        if(certificatesAndCertificateChain.isEmpty())
            return false;

        String expectedIssuerSubjectCN = this.ejbcaService.getCertificateAuthorityNameByCountry(countryCode);
        X509Certificate certificate = certificatesAndCertificateChain.get(0);
        X500Principal subjectX500Principal = certificate.getSubjectX500Principal();
        X500Name x500SubjectName = new X500Name(subjectX500Principal.getName());
        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500IssuerName = new X500Name(issuerX500Principal.getName());

        RDN[] rdnGivenName = x500SubjectName.getRDNs(BCStyle.GIVENNAME);
        if(rdnListContainsValue(rdnGivenName, givenName))
            return false;

        RDN[] rdnSurname = x500SubjectName.getRDNs(BCStyle.SURNAME);
        if(rdnListContainsValue(rdnSurname, surname))
            return false;

        RDN[] rdnSubjectCN = x500SubjectName.getRDNs(BCStyle.CN);
        if(rdnListContainsValue(rdnSubjectCN, subjectCN))
            return false;

        RDN[] rdnCountry = x500SubjectName.getRDNs(BCStyle.C);
        if(rdnListContainsValue(rdnCountry, countryCode))
            return false;

        RDN[] rdnIssuerSubjectCN = x500IssuerName.getRDNs(BCStyle.CN);
        return !rdnListContainsValue(rdnIssuerSubjectCN, expectedIssuerSubjectCN);
    }

    private static boolean rdnListContainsValue(RDN[] rdnListFromCertificate, String value){
        if(rdnListFromCertificate == null)
            return true;
        for (RDN rdn : rdnListFromCertificate) {
            String name = IETFUtils.valueToString(rdn.getFirst().getValue());
            if(name.equals(value))
                return false;
        }
        return true;
    }

    private static X509Certificate createSelfSignedCert(KeyPair keyPair) throws OperatorCreationException, CertificateException, IOException {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Date startDate = calendar.getTime();

        X500Name subjectDN = new X500Name("CN=subject_test");
        X500Name issuerDN = new X500Name("CN=issuer_test");

        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the
        // certificate serial number

        // calculate the timestamp for the end date
        calendar.setTime(startDate);
        calendar.add(Calendar.MONTH, 12);
        Date endDate = calendar.getTime();

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());

        // Use X509v3 Certificates per the CSC Standard
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerDN, certSerialNumber, startDate,
              endDate,
              subjectDN, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is
        // usually marked as
        // critical.

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
    }

}
