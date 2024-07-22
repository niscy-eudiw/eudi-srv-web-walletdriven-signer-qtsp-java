package eu.europa.ec.eudi.signer.r3.qtsp.model;


import eu.europa.ec.eudi.signer.r3.qtsp.model.certificates.CertificatesService;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.User;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.repositories.CredentialsRepository;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


public class DefaultVariables {

    private KeyPair kp;
    private X509Certificate cert;
    private final CredentialsRepository credentialsRepository;
    private final CertificatesService certificatesService;
    private final User user_for_tests;

    public DefaultVariables(CredentialsRepository credentialsRepository, CertificatesService certificatesService) throws Exception{
        this.credentialsRepository = credentialsRepository;
        this.certificatesService = certificatesService;
        this.user_for_tests = new User();
    }
    
    public void addDefaultCredentials(){
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
            System.out.println(this.kp);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(cert_bytes);
            this.cert = (X509Certificate) certFactory.generateCertificate(in);
            System.out.println(this.cert.toString());

            String publicKeyBase64 = Base64.getEncoder().encodeToString(this.kp.getPublic().getEncoded());
            String privateKeyBase64 = Base64.getEncoder().encodeToString(this.kp.getPrivate().getEncoded());

            if(this.credentialsRepository.existsByPrivateKeyAndPublicKeyAndCertificate(
                  publicKeyBase64,
                  privateKeyBase64,
                  this.certificatesService.base64EncodeCertificate(this.cert)
            ).isEmpty()){
                Credentials credential = new Credentials();
                credential.setId("cred1");
                credential.setUserID(this.user_for_tests.getId());
                credential.setDescription("This is a credential created locally for tests");
                credential.setSignatureQualifier("eu_eidas_qes");
                credential.setSCAL("2");
                credential.setMultisign(1);
                credential.setLang("en-US");

                credential.setPrivateKey(privateKeyBase64);
                credential.setPublicKey(publicKeyBase64);
                credential.setKeyStatus("enabled");
                List<String> keyAlgo = new ArrayList<>();
                keyAlgo.add("1.2.840.113549.1.1.1");
                keyAlgo.add("1.2.840.113549.1.1.11");
                credential.setKeyAlgo(keyAlgo);
                credential.setKeyLen(1024);

                credential.setCertStatus("valid");
                credential.setCertificate(this.certificatesService.base64EncodeCertificate(this.cert));
                credential.setCertificateChain(new ArrayList<>());

                credential.setAuthMode("oauth2code");
                this.credentialsRepository.save(credential);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
