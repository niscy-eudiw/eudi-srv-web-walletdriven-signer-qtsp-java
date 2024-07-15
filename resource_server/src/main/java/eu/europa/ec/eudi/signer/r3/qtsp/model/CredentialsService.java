package eu.europa.ec.eudi.signer.r3.qtsp.Model;

import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsInfo.CredentialsInfoCert;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsInfo.CredentialsInfoKey;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsInfoAuth;
import eu.europa.ec.eudi.signer.r3.qtsp.DTO.CredentialsListResponse;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Service
public class CredentialsService {

    private KeyPair kp;
    private X509Certificate cert;

    public CredentialsService(){
        try {
            byte[] pk_bytes = Base64.getDecoder().decode(
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCseUUmD8+Okuh5OrLT2LyO6QCNOIidohV7HAjIbgdpSU1C27z+JDWT3cfVbojQ5EzvZM9CDPayHrlnNK8NFD9ggE3rbOn6ATT9iC4qTQvPN3Sdel5OTaVabMuMT2satwbtl8wB98583i4bhJUyHRy7PJnXrOCscyK14GjGnuVwjQIDAQAB");
            byte[] sk_bytes = Base64.getDecoder().decode(
                    "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKx5RSYPz46S6Hk6stPYvI7pAI04iJ2iFXscCMhuB2lJTULbvP4kNZPdx9VuiNDkTO9kz0IM9rIeuWc0rw0UP2CATets6foBNP2ILipNC883dJ16Xk5NpVpsy4xPaxq3Bu2XzAH3znzeLhuElTIdHLs8mdes4KxzIrXgaMae5XCNAgMBAAECgYAP18PmTyV9rzjzidTLaOlJJ1YJotvJvw3CFT0pTBIaNcWHErA1mBXj00d7739Z0N7QTq5LHu26RuA4/rnltapsiBWWl3LXCkhx6qtthhVdQxZfO0fDQrujqjt++nHq1945qDh1t9VHmcDInVmHE/ZTtvzxroug4WRICiEfTOtrcQJBAOcKBAU096QUzADOAgIK72+a1JTuhljmpAe6RTDAaOn0mI/XYpdajQGptvDre3xaMzwTE8+Fm9ze5JIyh78Prq8CQQC/G3n8p0uhBHVvrLGrU72SSO5rAfVvxhhK6GcEF9f/YCxF87CLXFEzFOB9HmIx9xsVFJmIFH9y1bPGl9JvHQODAkAokN6h12n/2lLzdThvCWJ/Ew1uVO8r3ttALBmH9NC2+2ZqIyRBdPm7KARiCsa0z9WdH7BjyI7UWiKB9PNWvbcrAkAFserrtYySatCZGFtfEKrIjjXUqIVI5G1a5hwTyiYcrSAEoaN0M7cTv56E+//PH18GPMvqeznlESs/UszplMLDAkBs4LYp2Ycv1W6rTMj4f/lqP+NbY3eq6hvozk56Mt/FmhGY6zu/3xcLdnISLMjaJx2sZxq7aCAV21txFBlRekhU");
            byte[] cert_bytes = Base64.getDecoder().decode(
                    "MIIBuzCCASSgAwIBAgIGAY/zF0AhMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2lzc3Vlcl90ZXN0MB4XDTI0MDYwNzE0MjUzOFoXDTI1MDYwNzE0MjUzOFowFzEVMBMGA1UEAwwMc3ViamVjdF90ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCseUUmD8+Okuh5OrLT2LyO6QCNOIidohV7HAjIbgdpSU1C27z+JDWT3cfVbojQ5EzvZM9CDPayHrlnNK8NFD9ggE3rbOn6ATT9iC4qTQvPN3Sdel5OTaVabMuMT2satwbtl8wB98583i4bhJUyHRy7PJnXrOCscyK14GjGnuVwjQIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBACWKec1JiRggmTRm0aQin3SJnsvuF8JS5GlOpea45IGV2gOHws/iFPg8BAaGzQ1d+sG+RHH07xKCll8Xw1QaqLhc+96vNOCvl2cjl7BdLH/fiYurP8Vf0W3lkp5VbRFV2nWwHcOIPBUa8lNK+uV6Z5nPG5Ads12BJD5K8jAHXo2E");

            X509EncodedKeySpec spec = new X509EncodedKeySpec(pk_bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pKey = keyFactory.generatePublic(spec);

            PKCS8EncodedKeySpec spec2 = new PKCS8EncodedKeySpec(sk_bytes);
            PrivateKey sKey = keyFactory.generatePrivate(spec2);

            this.kp = new KeyPair(pKey, sKey);
            System.out.println(this.kp.toString());

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(cert_bytes);
            this.cert = (X509Certificate) certFactory.generateCertificate(in);
            System.out.println(this.cert.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    // to be implemented
    public List<String> getAvailableCredentialsID(String userID, boolean onlyValid){
        List<String> ids = new ArrayList<>();
        ids.add("example credential id");
        return ids;
    }

    // to be implemented
    public List<CredentialsListResponse.CredentialInfo> getCredentialInfo(String certificates, boolean certInfo, boolean authInfo, boolean onlyValid){
        List<CredentialsListResponse.CredentialInfo> result = new ArrayList<>();

        // for each available credential:

        CredentialsListResponse.CredentialInfo ci = new CredentialsListResponse.CredentialInfo();
        ci.setCredentialID("example credential id");

        CredentialsInfoKey key = new CredentialsInfoKey();
        key.setStatus("enabled");

        PublicKey pk = this.kp.getPublic();
        pk.getAlgorithm();
        System.out.println(pk.getAlgorithm());
        PrivateKey sk  = this.kp.getPrivate();
        sk.getAlgorithm();
        System.out.println(pk.getAlgorithm());

        //
        //key.setLen();

        ci.setKey(key);

        ci.setSCAL("2");

        ci.setMultisign(1);


        if(certInfo){
            CredentialsInfoCert cert = new CredentialsInfoCert();

            cert.setStatus("enabled");

            // return various parameters containing information from the end entity certificate
            switch (certificates){
                case "none":
                    cert.setCertificates(new ArrayList<>());
                    break;
                case "single":
                    List<String> c1 = new ArrayList<>();
                    c1.add(this.cert.toString());
                    cert.setCertificates(c1);
                    break;
                case "chain":
                    List<String> c2 = new ArrayList<>();
                    c2.add(this.cert.toString());
                    cert.setCertificates(c2);
                    break;
            }

            String issuerDN = this.cert.getIssuerDN().toString();
            cert.setIssuerDN(issuerDN);

            String serialNumber = this.cert.getSerialNumber().toString();
            cert.setSerialNumber(serialNumber);

            String subjectDN = this.cert.getSubjectDN().toString();
            cert.setSubjectDN(subjectDN);

            String validFrom = String.valueOf(this.cert.getNotBefore());
            String validTo = String.valueOf(this.cert.getNotAfter());
            cert.setValidFrom(validFrom);
            cert.setValidTo(validTo);
            ci.setCert(cert);
        }

        if(authInfo) {
            // return various parameters containing information on the authorization mechanisms supported by the corresponding credential.

            CredentialsInfoAuth auth = new CredentialsInfoAuth();
            auth.setMode("oauth2code?");
            if (auth.getMode().equals("explicit")) {
                auth.setExpression("...");
                auth.setObjects(new ArrayList<>());
            }

        }

        result.add(ci);

        return result;
    }

    // to be implemented
    public CredentialsListResponse.CredentialInfo getCredentialInfoFromSingleCredential(String credentialId, String certificates, boolean certInfo, boolean authInfo){
        CredentialsListResponse.CredentialInfo ci = new CredentialsListResponse.CredentialInfo();
        ci.setCredentialID(credentialId);
        return ci;
    }

    public static KeyPair keyPairGeneration() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static X509Certificate createSelfSignedCert(KeyPair keyPair)
            throws OperatorCreationException, CertificateException, IOException {
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

        final X509Certificate certificate = new JcaX509CertificateConverter().setProvider(bcProvider)
                .getCertificate(certBuilder.build(contentSigner));
        return certificate;
    }



    public static void createCredential(){

    }

}
