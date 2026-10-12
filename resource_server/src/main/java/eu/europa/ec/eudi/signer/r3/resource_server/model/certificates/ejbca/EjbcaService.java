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

package eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.*;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import org.json.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;

@Component
public class EjbcaService {

    private static final Logger log = LoggerFactory.getLogger(EjbcaService.class);

    private final EjbcaProperties ejbcaProperties;

    public EjbcaService(@Autowired EjbcaProperties properties) {
        this.ejbcaProperties = properties;
    }

    public String getCertificateAuthorityNameByCountry(String countryCode){
        return this.ejbcaProperties.getCertificateAuthorityName(countryCode);
    }

    // [0] : certificate
    // [1..] : certificate Chain
    public List<X509Certificate> certificateRequest(String certificateRequest, String countryCode) throws Exception {

        String certificateAuthorityName = this.ejbcaProperties.getCertificateAuthorityName(countryCode);
        String certificateRequestBody = getJsonBody(certificateRequest, certificateAuthorityName);
        String postUrl = "https://" + this.ejbcaProperties.getCahost() + "/ejbca/ejbca-rest-api/v1" + this.ejbcaProperties.getEndpoint();

        // Set up headers
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");

        String clientP12ArchiveFilepath = this.ejbcaProperties.getClientP12ArchiveFilepath();
        String clientP12ArchivePassword = this.ejbcaProperties.getClientP12ArchivePassword();
        KeyManager[] keyStorePKCS12 = getKeyStoreFromPKCS12File(clientP12ArchiveFilepath, clientP12ArchivePassword);
        String ManagementCA = this.ejbcaProperties.getManagementCA();
        TrustManager[] trustManagerCA = getTrustManagerOfCACertificate(ManagementCA);

        // Get Certificate from EJBCA
        HttpResponse response = WebUtils.httpPostRequestsWithCustomSSLContext(trustManagerCA, keyStorePKCS12, postUrl, certificateRequestBody, headers);

        if (response.getStatusLine().getStatusCode() != 201) {
            log.error(WebUtils.convertStreamToString(response.getEntity().getContent()));
            throw new Exception("Certificate was not created by EJBCA");
        }
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            throw new Exception("Message from EJBCA is empty");
        }
        InputStream inStream = entity.getContent();
        String result = WebUtils.convertStreamToString(inStream);

        return getCertificateFromHttpResponse(result);
    }

    private String getJsonBody(String certificateRequest, String certificateAuthorityName) {
        JSONObject JsonBody = new JSONObject();
        JsonBody.put("certificate_request", certificateRequest);
        JsonBody.put("certificate_profile_name", this.ejbcaProperties.getCertificateProfileName());
        JsonBody.put("end_entity_profile_name", this.ejbcaProperties.getEndEntityProfileName());
        JsonBody.put("certificate_authority_name", certificateAuthorityName);
        JsonBody.put("username", this.ejbcaProperties.getUsername());
        JsonBody.put("password", this.ejbcaProperties.getPassword());
        JsonBody.put("include_chain", this.ejbcaProperties.getIncludeChain());
        return JsonBody.toString();
    }

    private static KeyManager[] getKeyStoreFromPKCS12File(String PKCS12File, String PKCS12password) throws Exception {

        // Load PKCS#12 certificate
        KeyStore clientStore = KeyStore.getInstance("PKCS12");
        char[] password = PKCS12password.toCharArray();
        FileInputStream fis = new FileInputStream(PKCS12File);
        clientStore.load(fis, password);

        // Create KeyManagerFactory
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(clientStore, password);

        return keyManagerFactory.getKeyManagers();
    }

    private static TrustManager[] getTrustManagerOfCACertificate(String CAFilepath) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        if (CAFilepath == null) {
            return tmf.getTrustManagers();
        }

        CertificateFactory certificateFactory = CertificateFactory.getInstance("x509");
        FileInputStream caInputStream = new FileInputStream(CAFilepath);
        X509Certificate caCertificate = (X509Certificate) certificateFactory.generateCertificate(caInputStream);

        KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        caKeyStore.load(null, null);
        caKeyStore.setCertificateEntry("ca", caCertificate);
        tmf.init(caKeyStore);
        return tmf.getTrustManagers();
    }

    // [0] : certificate
    // [1..] : certificate Chain
    private List<X509Certificate> getCertificateFromHttpResponse(String result) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();

        JSONObject jsonResult;
        try{
            jsonResult = new JSONObject(result);
        }
        catch (JSONException e){
            throw new Exception("Response from EJBCA doesn't contain a correctly formatted json string.");
        }

        if (!jsonResult.keySet().contains("certificate")){
            throw new Exception("Response from EJBCA doesn't contain a certificate value.");
        }

        String certificateContent = jsonResult.getString("certificate");
        byte[] certificateBytes = Base64.getDecoder().decode(certificateContent);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        certs.add(certificate);

        // If the response from the EJBCA includes the Certificate Chain then get the
        // Certificate Chain from the response
        boolean includeChain = this.ejbcaProperties.getIncludeChain();
        if (includeChain && jsonResult.keySet().contains("certificate_chain")) {
            JSONArray certificateChain = jsonResult.getJSONArray("certificate_chain");
            for (int i = 0; i < certificateChain.length(); i++) {
                byte[] singleCertificateBytes = Base64.getDecoder().decode(certificateChain.getString(i));
                ByteArrayInputStream inputStreamSingleCertificate = new ByteArrayInputStream(singleCertificateBytes);
                X509Certificate singleCertificate = (X509Certificate) certificateFactory
                      .generateCertificate(inputStreamSingleCertificate);
                certs.add(singleCertificate);
            }
        }
        return certs;
    }

}