package eu.europa.ec.eudi.signer.r3.resource_server.model;

import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.CertificatesService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.CertificateChain;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.Credentials;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.User;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.CredentialsRepository;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.KeysService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoCert;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoKey;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo.CredentialsInfoAuth;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoResponse;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;

import java.util.*;


@Service
public class CredentialsService {

    private final CertificatesService certificatesService;
    private final CredentialsRepository credentialsRepository;
    private final KeysService keysService;
    private final User user_for_tests;

    public CredentialsService(
          @Autowired HsmService hsmService,
          @Autowired EjbcaService ejbcaService,
          @Autowired CredentialsRepository credentialsRepository
    ) throws Exception{
        this.credentialsRepository = credentialsRepository;
        this.keysService = new KeysService(hsmService);
        this.certificatesService = new CertificatesService(hsmService, ejbcaService);
        this.user_for_tests = new User();

        DefaultVariables defaultVariables = new DefaultVariables(this.credentialsRepository, this.certificatesService);
        defaultVariables.addDefaultCredentials();
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

        String privateKeyBase64 = Base64.getEncoder().encodeToString(privKeyValues);
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        credential.setPrivateKey(privateKeyBase64);
        credential.setPublicKey(publicKeyBase64);
        credential.setKeyStatus("enabled");
        List<String> keyAlgo = new ArrayList<>();
        keyAlgo.add("1.2.840.113549.1.1.1");
        keyAlgo.add("1.2.840.113549.1.1.11");
        credential.setKeyAlgo(keyAlgo);
        credential.setKeyLen(1024);

        credential.setCertStatus("valid");
        credential.setCertificate(this.certificatesService.base64EncodeCertificate(ejbcaCert));
        credential.setCertificateChain(certs);

        credential.setAuthMode("oauth2code");
        this.credentialsRepository.save(credential);
    }
}
