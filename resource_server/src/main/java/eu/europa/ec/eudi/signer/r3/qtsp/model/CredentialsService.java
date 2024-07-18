package eu.europa.ec.eudi.signer.r3.qtsp.model;

import eu.europa.ec.eudi.signer.r3.qtsp.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.qtsp.model.certificates.CertificatesService;
import eu.europa.ec.eudi.signer.r3.qtsp.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.CertificateChain;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.SecretKey;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.User;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.repositories.CredentialsRepository;
import eu.europa.ec.eudi.signer.r3.qtsp.model.database.repositories.SecretKeyRepository;
import eu.europa.ec.eudi.signer.r3.qtsp.model.keys.KeysService;
import eu.europa.ec.eudi.signer.r3.qtsp.model.keys.hsm.HsmService;
import eu.europa.ec.eudi.signer.r3.qtsp.web.dto.CredentialsInfo.CredentialsInfoCert;
import eu.europa.ec.eudi.signer.r3.qtsp.web.dto.CredentialsInfo.CredentialsInfoKey;
import eu.europa.ec.eudi.signer.r3.qtsp.web.dto.CredentialsInfo.CredentialsInfoAuth;
import eu.europa.ec.eudi.signer.r3.qtsp.web.dto.CredentialsInfoResponse;
import eu.europa.ec.eudi.signer.r3.qtsp.web.dto.CredentialsListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


@Service
public class CredentialsService {

    private HsmService hsmService;
    private EjbcaService ejbcaService;
    private KeyPair kp;
    private X509Certificate cert;
    private final KeysService keysService;
    private final CertificatesService certificatesService;
    private final User user_for_tests;
    private final CredentialsRepository credentialsRepository;
    private static final int IVLENGTH = 12;


    public CredentialsService(@Autowired HsmService hsmService, @Autowired EjbcaService ejbcaService,
                              @Autowired CredentialsRepository credentialsRepository, @Autowired SecretKeyRepository secretKeyRepositoryLoaded,
                              @Autowired AuthConfig authProperties) throws Exception{
        this.hsmService = hsmService;
        this.ejbcaService = ejbcaService;
        this.credentialsRepository = credentialsRepository;
        this.keysService = new KeysService(this.hsmService);
        this.certificatesService = new CertificatesService(this.hsmService, this.ejbcaService);
        this.user_for_tests = new User();

        char[] passphrase = authProperties.getDbEncryptionPassphrase().toCharArray();
        byte[] saltBytes = Base64.getDecoder().decode(authProperties.getDbEncryptionSalt());
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec encryptionKeySpec = new PBEKeySpec(passphrase, saltBytes, 65536, 256);
        Key encryptionKey = new SecretKeySpec(factory.generateSecret(encryptionKeySpec).getEncoded(), "AES");

        List<SecretKey> secretKeys = secretKeyRepositoryLoaded.findAll();
        if (secretKeys.isEmpty()) {
            // generates a secret key to wrap the private keys from the HSM
            byte[] secretKeyBytes = this.hsmService.initSecretKey();

            byte[] iv = new byte[IVLENGTH];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            // encrypts the secret key before saving it in the db
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec algSpec = new GCMParameterSpec(128, iv);
            c.init(Cipher.ENCRYPT_MODE, encryptionKey, algSpec);
            byte[] encryptedSecretKeyBytes = c.doFinal(secretKeyBytes);

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedSecretKeyBytes.length);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedSecretKeyBytes);

            SecretKey secretKey = new SecretKey(byteBuffer.array());
            secretKeyRepositoryLoaded.save(secretKey);
        } else {
            SecretKey sk = secretKeys.get(0);
            byte[] encryptedSecretKeyBytes = sk.getSecretKey();

            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedSecretKeyBytes);
            byte[] iv = new byte[IVLENGTH];
            byteBuffer.get(iv);
            byte[] encryptedSecretKey = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedSecretKey);

            // decrypts the secret key
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec algSpec = new GCMParameterSpec(128, iv);
            c.init(Cipher.DECRYPT_MODE, encryptionKey, algSpec);
            byte[] secretKeyBytes = c.doFinal(encryptedSecretKey);

            this.hsmService.setSecretKey(secretKeyBytes);
        }

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

            /*Credentials credential = new Credentials();
            credential.setUserID(this.user_for_tests.getId());
            credential.setDescription("This is a credential created locally for tests");
            credential.setSignatureQualifier("eu_eidas_qes");
            credential.setSCAL("2");
            credential.setMultisign(1);
            credential.setLang("en-US");

            credential.setPrivateKey(this.kp.getPrivate().getEncoded());
            credential.setPublicKey(this.kp.getPublic().getEncoded());
            credential.setKeyStatus("enabled");
            List<String> keyAlgo = new ArrayList<>();
            keyAlgo.add("1.2.840.113549.1.1.1");
            credential.setKeyAlgo(keyAlgo);
            credential.setKeyLen(1024);

            credential.setCertStatus("valid");
            credential.setCertificate(this.certificatesService.base64EncodeCertificate(this.cert));
            credential.setCertificateChain(new ArrayList<>());

            credential.setAuthMode("oauth2code");
            this.credentialsRepository.save(credential);*/
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Function that returns the list of the credentials id available to the user
     * @param userID the user that made the request and that owns the credentials
     * @param onlyValid a parameter that defines if the credentials returned are valid and can be used to sign
     * @return the list of the credentials id
     */
    public List<String> getAvailableCredentialsID(String userID, boolean onlyValid){
        List<Credentials> credentials = this.credentialsRepository.findByUserID(userID);
        List<String> listAvailableCredentials;
        if(!onlyValid)
            listAvailableCredentials = credentials.stream().map(Credentials :: getId).toList();
        else
            listAvailableCredentials = credentials.stream().filter(Credentials::isValid).map(Credentials::getId).toList();
        return listAvailableCredentials;
    }

    /**
     * Function that returns the list of credential info
     * @param listAvailableCredentials the list of the available credentials to an user, retrieved previously
     * @param certificates the value used to determine if the response should contain the end-entity certificate, the certificate chain or none
     * @param certInfo the parameter used to determine if the response contains additional information about the end-entity certificate
     * @param authInfo the parameter used to determine if the response contains authorization information
     * @return a list with information of the credentials in the available credentials list
     * @throws Exception
     */
    public List<CredentialsListResponse.CredentialInfo> getCredentialInfo( List<String> listAvailableCredentials, String certificates, boolean certInfo, boolean authInfo ) throws Exception{
        List<CredentialsListResponse.CredentialInfo> listOfCredentialInfo = new ArrayList<>();

        for (String credentialId: listAvailableCredentials){
            CredentialsListResponse.CredentialInfo ci = new CredentialsListResponse.CredentialInfo();
            ci.setCredentialID(credentialId);

            Optional<Credentials> optionalCredential =  this.credentialsRepository.findById(credentialId);
            if(optionalCredential.isEmpty()) continue;

            Credentials credential = optionalCredential.get();
            ci.setDescription(credential.getDescription());
            ci.setSignatureQualifier(credential.getSignatureQualifier());
            ci.setSCAL(credential.getSCAL());
            ci.setMultisign(credential.getMultisign());
            ci.setLang(credential.getLang());
            ci.setKey(getCredentialsKeyInfo(credential));
            ci.setCert(getCredentialsCertInfo(credential, certificates, certInfo));
            if(authInfo){
                CredentialsInfoAuth credentialsInfoAuth = getCredentialsAuthInfo(credential);
                ci.setAuth(credentialsInfoAuth);
            }
            listOfCredentialInfo.add(ci);
        }
        return listOfCredentialInfo;
    }

    /**
     * Function that allows to get information about the Credential
     * @param credentialId the id of the credential
     * @param certificates the value used to determine if the response should contain the end-entity certificate, the certificate chain or none
     * @param certInfo the parameter used to determine if the response contains additional information about the end-entity certificate
     * @param authInfo the parameter used to determine if the response contains authorization information
     * @return the information about the Credential
     * @throws Exception
     */
    public CredentialsInfoResponse getCredentialInfoFromSingleCredential(String credentialId, String certificates, boolean certInfo, boolean authInfo) throws Exception {
        CredentialsInfoResponse credentialsInfoResponse = new CredentialsInfoResponse();

        Optional<Credentials> credentialOptional = this.credentialsRepository.findById(credentialId);
        if(credentialOptional.isEmpty()) return null;

        Credentials credential = credentialOptional.get();
        credentialsInfoResponse.setDescription(credential.getDescription());
        credentialsInfoResponse.setSignatureQualifier(credential.getSignatureQualifier());
        credentialsInfoResponse.setSCAL(credential.getSCAL());
        credentialsInfoResponse.setMultisign(credential.getMultisign());
        credentialsInfoResponse.setLang(credential.getLang());
        credentialsInfoResponse.setKey(getCredentialsKeyInfo(credential));
        credentialsInfoResponse.setCert(getCredentialsCertInfo(credential, certificates, certInfo));
        if(authInfo){
            CredentialsInfoAuth credentialsInfoAuth = getCredentialsAuthInfo(credential);
            credentialsInfoResponse.setAuth(credentialsInfoAuth);
        }
        return credentialsInfoResponse;
    }

    private CredentialsInfoKey getCredentialsKeyInfo(Credentials credential){
        CredentialsInfoKey credentialsInfoKey = new CredentialsInfoKey();
        credentialsInfoKey.setAlgo(credential.getKeyAlgo());
        credentialsInfoKey.setStatus(credential.getKeyStatus());
        credentialsInfoKey.setCurve(credential.getKeyCurve());
        credentialsInfoKey.setLen(credential.getKeyLen());
        return credentialsInfoKey;
    }

    private CredentialsInfoCert getCredentialsCertInfo(Credentials credential, String certificates, boolean certInfo) throws Exception{
        CredentialsInfoCert credentialsInfoCert = new CredentialsInfoCert();
        credentialsInfoCert.setStatus(credential.getCertStatus());

        if(certificates.equals("single")){
            List<String> certificatesList = new ArrayList<>();
            certificatesList.add(credential.getCertificate());
            credentialsInfoCert.setCertificates(certificatesList);
        }
        else if(certificates.equals("chain")){
            List<String> certificatesList = new ArrayList<>();
            certificatesList.add(credential.getCertificate());
            certificatesList.addAll(credential.getCertificateChain());
            credentialsInfoCert.setCertificates(certificatesList);
        }

        if(certInfo){
            String certificateEncoded = credential.getCertificate();
            X509Certificate x509Certificate = certificatesService.base64DecodeCertificate(certificateEncoded);

            credentialsInfoCert.setIssuerDN(x509Certificate.getIssuerDN().getName());
            credentialsInfoCert.setSerialNumber(String.valueOf(x509Certificate.getSerialNumber()));
            credentialsInfoCert.setSubjectDN(x509Certificate.getSubjectDN().getName());
            credentialsInfoCert.setValidTo(x509Certificate.getNotAfter().toString());
            credentialsInfoCert.setValidFrom(x509Certificate.getNotBefore().toString());
        }
        return credentialsInfoCert;
    }

    private CredentialsInfoAuth getCredentialsAuthInfo(Credentials credential){
        CredentialsInfoAuth infoAuth = new CredentialsInfoAuth();
        infoAuth.setMode(credential.getAuthMode());
        if (credential.getAuthMode().equals("explicit")){
            infoAuth.setExpression(credential.getAuthExpression());
            infoAuth.setObjects(credential.getAuthObjects());
        }
        return infoAuth;
    }

    public void createCredential() throws Exception{
        Credentials credential = new Credentials();

        byte[][] keysValues = this.keysService.RSAKeyPairGeneration();

        byte[] privKeyValues = keysValues[0];
        byte[] modulus = keysValues[1];
        BigInteger ModulusBI = new BigInteger(1, modulus);
        byte[] public_exponent = keysValues[2];
        BigInteger PublicExponentBI = new BigInteger(1, public_exponent);
        PublicKey publicKey = this.keysService.getRSAPublicKeyFromSpecs(ModulusBI, PublicExponentBI);

        List<X509Certificate> EJBCACertificates = this.certificatesService.generateCertificates(publicKey, this.user_for_tests.getGivenName(), this.user_for_tests.getSurname(), this.user_for_tests.getName(), this.user_for_tests.getIssuingCountry(), privKeyValues);
        X509Certificate ejbcaCert = EJBCACertificates.get(0);
        List<CertificateChain> certs = new ArrayList<>();
        if (EJBCACertificates.size() > 1) {
            List<X509Certificate> ejbcaCertificateChain = EJBCACertificates.subList(1, EJBCACertificates.size());
            for (X509Certificate x509Certificate : ejbcaCertificateChain) {
                CertificateChain cert = new CertificateChain();
                cert.setCertificate(this.certificatesService.base64EncodeCertificate(x509Certificate));
                cert.setCredential(credential);
                certs.add(cert);
            }
        }

        credential.setUserID(this.user_for_tests.getId());
        credential.setDescription("This is a credential for tests");
        credential.setSignatureQualifier("eu_eidas_qes");
        credential.setSCAL("2");
        credential.setMultisign(1);
        credential.setLang("en-US");

        credential.setPrivateKey(privKeyValues);
        credential.setPublicKey(publicKey.getEncoded());
        credential.setKeyStatus("enabled");
        List<String> keyAlgo = new ArrayList<>();
        keyAlgo.add("1.2.840.113549.1.1.1");
        credential.setKeyAlgo(keyAlgo);
        credential.setKeyLen(1024);

        credential.setCertStatus("valid");
        credential.setCertificate(this.certificatesService.base64EncodeCertificate(ejbcaCert));
        credential.setCertificateChain(certs);

        credential.setAuthMode("oauth2code");
        this.credentialsRepository.save(credential);
    }
}
