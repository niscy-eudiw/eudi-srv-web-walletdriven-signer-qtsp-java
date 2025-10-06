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

package eu.europa.ec.eudi.signer.r3.resource_server.model.certificates;

import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/***
 * The module response for managing certificates and certificate chains
 */
public class CertificatesService {
    private final HsmService hsmService;
    private final EjbcaService ejbcaService;
    private static final Logger logger = LoggerFactory.getLogger(CertificatesService.class);

    public CertificatesService(HsmService hsmService, EjbcaService ejbcaService){
        this.hsmService = hsmService;
        this.ejbcaService = ejbcaService;
    }

    public String base64EncodeCertificate(X509Certificate certificate) throws Exception{
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    public X509Certificate base64DecodeCertificate(String certificate) throws Exception{
        byte[] certificateBytes = Base64.getDecoder().decode(certificate);
        ByteArrayInputStream inputStream  =  new ByteArrayInputStream(certificateBytes);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)certFactory.generateCertificate(inputStream);
    }

    public List<X509Certificate> generateRSACertificates(PublicKey publicKey, String givenName, String surname, String subjectCN, String countryCode, byte[] privateKeyValues) throws Exception {
        return generateCertificates(publicKey, givenName, surname, subjectCN, countryCode, privateKeyValues, "RSA");
    }

    public List<X509Certificate> generateP256Certificates(PublicKey publicKey, String givenName, String surname, String subjectCN, String countryCode, byte[] privateKeyValues) throws Exception {
        return generateCertificates(publicKey, givenName, surname, subjectCN, countryCode, privateKeyValues, "ECDSA");
    }

    private List<X509Certificate> generateCertificates(PublicKey publicKey, String givenName, String surname, String subjectCN, String countryCode, byte[] privateKeyValues, String keyAlgorithm) throws Exception{

        byte[] csrInfo = generateCertificateRequestInfo(publicKey, givenName, surname, subjectCN, countryCode);
        logger.info("Retrieved Certificate Signing Request Information.");

        PKCS10CertificationRequest certificateHSM = generateCertificateRequest(privateKeyValues, csrInfo, keyAlgorithm);
        String certificateString = "-----BEGIN CERTIFICATE REQUEST-----\n" + new String(Base64.getEncoder().encode(certificateHSM.getEncoded())) + "\n" + "-----END CERTIFICATE REQUEST-----";
        logger.info("Generated the Certificate Signing Request.");

        // Makes a request to the CA
        List<X509Certificate> certificateAndCertificateChain = this.ejbcaService.certificateRequest(certificateString, countryCode);
        logger.info("Retrieved the certificate and certificate chain from the CA.");
        if(!validateCertificateFromCA(certificateAndCertificateChain, givenName, surname, subjectCN, countryCode)){
            throw new Exception("Certificates received from CA are not valid");
        }
        logger.info("Validated the certificate and certificate chain received from the CA.");
        return certificateAndCertificateChain;
    }


    private byte[] generateCertificateRequestInfo(PublicKey publicKey, String givenName, String surname, String commonName, String countryName) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        final X500Name subjectDN = new X500NameBuilder(BCStyle.INSTANCE)
              .addRDN(BCStyle.CN, commonName)
              .addRDN(BCStyle.SURNAME, surname)
              .addRDN(BCStyle.GIVENNAME, givenName)
              .addRDN(BCStyle.C, countryName)
              .build();
		logger.info("Generating Certificate Signing Request Info: {}", subjectDN.toString());

        CertificationRequestInfo cri = new CertificationRequestInfo(subjectDN, pki, new DERSet());
        return cri.getEncoded();
    }

    private PKCS10CertificationRequest generateCertificateRequest( byte[] privateKeyValues, byte[] certRequestInfo, String keyAlgorithm) throws Exception {
        byte[] signature = null;
        AlgorithmIdentifier algorithmIdentifier = null;
        if(keyAlgorithm.equals("RSA")) {
            signature = hsmService.signDTBSWithRSAAndSHA256(privateKeyValues, certRequestInfo);
            algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        }
        else if(keyAlgorithm.equals("ECDSA")){
            signature = hsmService.signDTBSWithECDSAAndSHA256(privateKeyValues, certRequestInfo);
            algorithmIdentifier = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        }

        CertificationRequestInfo cri = CertificationRequestInfo.getInstance(certRequestInfo);
        DERBitString sig = new DERBitString(signature);
        CertificationRequest cr = new CertificationRequest(cri, algorithmIdentifier, sig);
        return new PKCS10CertificationRequest(cr);
    }

    private boolean validateCertificateFromCA(List<X509Certificate> certificatesAndCertificateChain, String expectedGivenName, String expectedSurname, String expectedSubjectCN, String expectedCountryCode){
        if(certificatesAndCertificateChain.isEmpty()) {
            logger.info("No certificate or certificate chain was received from the CA. The list of certificates is empty.");
            return false;
        }

        X509Certificate certificate = certificatesAndCertificateChain.get(0);
        X500Principal subjectX500Principal = certificate.getSubjectX500Principal();
        X500Name x500SubjectName = new X500Name(subjectX500Principal.getName());

        RDN[] rdnGivenName = x500SubjectName.getRDNs(BCStyle.GIVENNAME);
        if(rdnListContainsValue(rdnGivenName, expectedGivenName)) {
            StringBuilder sb = new StringBuilder();
            Arrays.stream(rdnGivenName).forEach(it -> {
                String value = IETFUtils.valueToString(it.getFirst().getValue());
                sb.append(value).append(", ");
            });
            logger.info("The expected GivenName ({}) was not found in the certificate received ({}).", expectedGivenName, sb);
            return false;
        }

        RDN[] rdnSurname = x500SubjectName.getRDNs(BCStyle.SURNAME);
        if(rdnListContainsValue(rdnSurname, expectedSurname)) {
            StringBuilder sb = new StringBuilder();
            Arrays.stream(rdnSurname).forEach(it -> {
                String value = IETFUtils.valueToString(it.getFirst().getValue());
                sb.append(value).append(", ");
            });
            logger.info("The expected Surname ({}) was not found in the certificate received ({}).", expectedSurname, sb);
            return false;
        }

        RDN[] rdnSubjectCN = x500SubjectName.getRDNs(BCStyle.CN);
        if(rdnListContainsValue(rdnSubjectCN, expectedSubjectCN)) {
            StringBuilder sb = new StringBuilder();
            Arrays.stream(rdnSubjectCN).forEach(it -> {
                String value = IETFUtils.valueToString(it.getFirst().getValue());
                sb.append(value).append(", ");
            });
            logger.info("The expected CommonName ({}) was not found in the certificate received ({}).", expectedSubjectCN, sb);
            return false;
        }

        RDN[] rdnCountry = x500SubjectName.getRDNs(BCStyle.C);
        if(rdnListContainsValue(rdnCountry, expectedCountryCode)) {
            StringBuilder sb = new StringBuilder();
            Arrays.stream(rdnCountry).forEach(it -> {
                String value = IETFUtils.valueToString(it.getFirst().getValue());
                sb.append(value).append(", ");
            });
            logger.info("The expected Country ({}) was not found in the certificate received ({}).", expectedCountryCode, sb);
            return false;
        }

        String expectedIssuerSubjectCN = this.ejbcaService.getCertificateAuthorityNameByCountry(expectedCountryCode);
        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500IssuerName = new X500Name(issuerX500Principal.getName());
        RDN[] rdnIssuerSubjectCN = x500IssuerName.getRDNs(BCStyle.CN);
        if(rdnListContainsValue(rdnIssuerSubjectCN, expectedIssuerSubjectCN)){
            StringBuilder sb = new StringBuilder();
            Arrays.stream(rdnIssuerSubjectCN).forEach(it -> {
                String value = IETFUtils.valueToString(it.getFirst().getValue());
                sb.append(value).append(", ");
            });
            logger.info("The expected Issuer ({}) was not found in the certificate received ({}).", expectedIssuerSubjectCN, sb);
            return false;
        }
        return true;
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
}
