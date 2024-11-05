package eu.europa.ec.eudi.signer.r3.resource_server.model;

import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.CertificatesService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.CertificateChain;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.CredentialsRepository;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.KeyPairRegister;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.KeysService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoCert;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoKey;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoAuth;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoResponse;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListResponse;

import java.text.SimpleDateFormat;
import java.util.*;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CredentialsService {

    private final CertificatesService certificatesService;
    private final CredentialsRepository credentialsRepository;
    private final KeysService keysService;

    public CredentialsService(@Autowired HsmService hsmService, @Autowired EjbcaService ejbcaService,
          @Autowired CredentialsRepository credentialsRepository){
        this.credentialsRepository = credentialsRepository;
        this.keysService = new KeysService(hsmService);
        this.certificatesService = new CertificatesService(hsmService, ejbcaService);
    }

    /**
     * Function that returns the list of the credentials id available to the user
     * @param userID the user that made the request and that owns the credentials (userHash)
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

    public boolean existsActiveCertificate(List<String> listAvailableCredentials){
        for (String credentialId: listAvailableCredentials){
            Optional<Credentials> optionalCredential = this.credentialsRepository.findById(credentialId);
            if (optionalCredential.isEmpty()) continue;
            Credentials credential = optionalCredential.get();
            try {
                this.certificatesService.base64DecodeCertificate(credential.getCertificate()).checkValidity();
                return true;
            } catch (Exception ignored) {}
        }
        return false;
    }

    /**
     * Function that returns the list of credential info
     * @param listAvailableCredentials the list of the available credentials to a user, retrieved previously
     * @param certificates the value used to determine if the response should contain the end-entity certificate, the certificate chain or none
     * @param certInfo the parameter used to determine if the response contains additional information about the end-entity certificate
     * @param authInfo the parameter used to determine if the response contains authorization information
     * @return a list with information of the credentials in the available credentials list
     */
    public List<CredentialsListResponse.CredentialInfo> getCredentialInfo(List<String> listAvailableCredentials,
                                                                          String certificates, boolean certInfo,
                                                                          boolean authInfo) throws Exception{
        List<CredentialsListResponse.CredentialInfo> listOfCredentialInfo = new ArrayList<>();
        for (String credentialId: listAvailableCredentials){
            Optional<Credentials> optionalCredential =  this.credentialsRepository.findById(credentialId);
            if(optionalCredential.isEmpty()) continue;

            Credentials credential = optionalCredential.get();
            CredentialsListResponse.CredentialInfo ci = new CredentialsListResponse.CredentialInfo();
            ci.setCredentialID(credentialId);
            ci.setDescription(credential.getDescription());
            ci.setSignatureQualifier(credential.getSignatureQualifier());
            ci.setSCAL(credential.getSCAL());
            ci.setMultisign(credential.getMultisign());
            ci.setLang(credential.getLang());
            ci.setKey(getCredentialsKeyInfo(credential));
            ci.setCert(getCredentialsCertInfo(credential, certificates, certInfo));
            if(authInfo) ci.setAuth(getCredentialsAuthInfo(credential));

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
     */
    public CredentialsInfoResponse getCredentialInfoFromSingleCredential(String credentialId, String certificates,
            boolean certInfo, boolean authInfo) throws Exception {
        Optional<Credentials> credentialOptional = this.credentialsRepository.findById(credentialId);
        if(credentialOptional.isEmpty()) return null;

        Credentials credential = credentialOptional.get();
        CredentialsInfoResponse credentialsInfoResponse = new CredentialsInfoResponse();
        credentialsInfoResponse.setDescription(credential.getDescription());
        credentialsInfoResponse.setSignatureQualifier(credential.getSignatureQualifier());
        credentialsInfoResponse.setSCAL(credential.getSCAL());
        credentialsInfoResponse.setMultisign(credential.getMultisign());
        credentialsInfoResponse.setLang(credential.getLang());
        credentialsInfoResponse.setKey(getCredentialsKeyInfo(credential));
        credentialsInfoResponse.setCert(getCredentialsCertInfo(credential, certificates, certInfo));
        if(authInfo) credentialsInfoResponse.setAuth(getCredentialsAuthInfo(credential));
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


            String patternDate = "YYYYMMDDHHMMSSZ";
            SimpleDateFormat simpleDateFormatter = new SimpleDateFormat(patternDate);
            Date validTo = x509Certificate.getNotAfter();
            Date validFrom = x509Certificate.getNotBefore();
            credentialsInfoCert.setValidTo(new ASN1GeneralizedTime(validTo).getTimeString());
            credentialsInfoCert.setValidFrom(new ASN1GeneralizedTime(validFrom).getTimeString());
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

    /**
     * Function that allows to create a credential (key pair and certificate) based on the RSA algorithm
     * @param userHash the hash of the user to whom the credential is created
     * @param givenName the given name of the user to be present in the certificate
     * @param surname the surname of the user to be present in the certificate
     * @param name the full name of the user to be used as CN
     * @param issuingCountry the country to be used in the certificate
     */
    public void createRSACredential(String userHash, String givenName, String surname, String name, String issuingCountry)
        throws Exception{
        int keySizeInBits = 2048;
        Credentials credential = new Credentials();
        KeyPairRegister keysValues = this.keysService.generateRSAKeyPair(keySizeInBits);

        List<X509Certificate> EJBCACertificates = this.certificatesService.generateRSACertificates(keysValues.getPublicKeyValue(),
              givenName, surname, name, issuingCountry, keysValues.getPrivateKeyBytes());
        X509Certificate signingCertificate = EJBCACertificates.get(0);
        List<X509Certificate> certificateChain = EJBCACertificates.subList(1, EJBCACertificates.size());

        List<CertificateChain> certs = new ArrayList<>();
        for (X509Certificate x509Certificate : certificateChain) {
                CertificateChain cert = new CertificateChain();
                cert.setCertificate(this.certificatesService.base64EncodeCertificate(x509Certificate));
                cert.setCredential(credential);
                certs.add(cert);
        }
        credential.setUserID(userHash);
        credential.setDescription("This is a credential for tests");
        credential.setSignatureQualifier("eu_eidas_qes");
        credential.setSCAL("2");
        credential.setMultisign(1);
        credential.setLang("en-US");
        credential.setPrivateKey(Base64.getEncoder().encodeToString(keysValues.getPrivateKeyBytes()));
        credential.setPublicKey( Base64.getEncoder().encodeToString(keysValues.getPublicKeyValue().getEncoded()));
        credential.setKeyStatus("enabled");
        List<String> keyAlgo = new ArrayList<>();
        keyAlgo.add("1.2.840.113549.1.1.1"); // rsaEncryption
        keyAlgo.add("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
        keyAlgo.add("1.2.840.113549.1.1.12"); // sha384WithRSAEncryption
        keyAlgo.add("1.2.840.113549.1.1.13"); // sha512WithRSAEncryption
        credential.setKeyAlgo(keyAlgo);
        credential.setKeyLen(keySizeInBits);
        credential.setCertStatus("valid");
        credential.setCertificate(this.certificatesService.base64EncodeCertificate(signingCertificate));
        credential.setCertificateChain(certs);
        credential.setAuthMode("oauth2code");
        this.credentialsRepository.save(credential);
    }

    /**
     * Function that allows to create a credential (key pair and certificate) based on the EC (P-256) algorithm
     * @param userHash the hash of the user to whom the credential is created
     * @param givenName the given name of the user to be present in the certificate
     * @param surname the surname of the user to be present in the certificate
     * @param name the full name of the user to be used as CN
     * @param issuingCountry the country to be used in the certificate
     */
    public void createECDSAP256Credential(String userHash, String givenName, String surname, String name, String issuingCountry)
          throws Exception{
        Credentials credential = new Credentials();
        KeyPairRegister keyValues = this.keysService.generateP256KeyPair();

        List<X509Certificate> EJBCACertificates = this.certificatesService.generateP256Certificates(keyValues.getPublicKeyValue(), givenName,
              surname, name, issuingCountry, keyValues.getPrivateKeyBytes());
        X509Certificate signingCertificate = EJBCACertificates.get(0);

        List<X509Certificate> certificateChain = EJBCACertificates.subList(1, EJBCACertificates.size());

        List<CertificateChain> certs = new ArrayList<>();
        for (X509Certificate x509Certificate : certificateChain) {
            CertificateChain cert = new CertificateChain();
            cert.setCertificate(this.certificatesService.base64EncodeCertificate(x509Certificate));
            cert.setCredential(credential);
            certs.add(cert);
        }
        credential.setUserID(userHash);
        credential.setDescription("This is a credential for tests");
        credential.setSignatureQualifier("eu_eidas_qes");
        credential.setSCAL("2");
        credential.setMultisign(1);
        credential.setLang("en-US");
        credential.setPrivateKey(Base64.getEncoder().encodeToString(keyValues.getPrivateKeyBytes()));
        credential.setPublicKey(Base64.getEncoder().encodeToString(keyValues.getPublicKeyValue().getEncoded()));
        credential.setKeyStatus("enabled");
        List<String> keyAlgo = new ArrayList<>();
        keyAlgo.add("1.2.840.10045.2.1"); // ecPublicKey
        keyAlgo.add("1.2.840.10045.4.3.2"); // ecdsa-with-SHA256
        keyAlgo.add("1.2.840.10045.4.3.3"); // ecdsa-with-SHA384
        keyAlgo.add("1.2.840.10045.4.3.4"); // ecdsa-with-SHA512
        credential.setKeyAlgo(keyAlgo);
        credential.setKeyLen(256);
        credential.setKeyCurve("1.2.840.10045.3.1.7");
        credential.setCertStatus("valid");
        credential.setCertificate(this.certificatesService.base64EncodeCertificate(signingCertificate));
        credential.setCertificateChain(certs);
        credential.setAuthMode("oauth2code");
        this.credentialsRepository.save(credential);
    }

    /**
     * Function that checks if a credential ID belongs to a user
     * @param userId the user identifier
     * @param credentialId the identifier of the user
     * @return boolean
     */
    public boolean credentialBelongsToUser(String userId, String credentialId){
        Optional<String> credentials = this.credentialsRepository.findByUserIDAndId(userId, credentialId);
        return credentials.isPresent();
    }
}
