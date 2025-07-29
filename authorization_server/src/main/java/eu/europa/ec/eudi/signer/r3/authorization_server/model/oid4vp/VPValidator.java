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

package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.TrustedIssuersCertificateConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.VerifiablePresentationVerificationException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import COSE.AlgorithmID;
import id.walt.mdoc.COSECryptoProviderKeyInfo;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import id.walt.mdoc.cose.COSESign1;
import id.walt.mdoc.dataretrieval.DeviceResponse;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.mso.ValidityInfo;
import kotlinx.datetime.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VPValidator {
    private static final Logger logger = LoggerFactory.getLogger(VPValidator.class);
    private final JSONObject verifiablePresentation;
    private final String presentationDefinitionInputDescriptorsId;
    private final String presentationDefinitionId;
    private final String keyID;
    private final TrustedIssuersCertificateConfig trustedIssuersCertificate;

    public VPValidator(JSONObject vp, String presentation_definition_id, String presentation_definition_input_descriptors_id, TrustedIssuersCertificateConfig trustedIssuersCertificate) {
        this.verifiablePresentation = vp;
        this.presentationDefinitionId = presentation_definition_id;
        this.presentationDefinitionInputDescriptorsId = presentation_definition_input_descriptors_id;
        this.keyID = "keyID";
        this.trustedIssuersCertificate = trustedIssuersCertificate;
    }

    /**
     * Function that allows verification of the Presentation Submission in the
     * Response from the Verifier.
     * This function verifies if the Presentation Submission has the required
     * definition_id, which should be equal to the one defined in the Presentation
     * Definition in the Request.
     * This function verifies if the Descriptor_Map from the Presentation Submission
     * also contains the requested value, in a supported format.
     * 
     * @return the position in the array documents of the vp_token where the
     *         requested Verifiable Presentation is located.
     */
    private int validatePresentationSubmission() throws OID4VPException, JSONException {
        JSONObject presentation_submission = this.verifiablePresentation.getJSONObject("presentation_submission");

        if (!presentation_submission.getString("definition_id").equals(this.presentationDefinitionId)) {
            logger.error("The definition_id from the presentation_submission doesn't match the expected {}", this.presentationDefinitionId);
            throw new OID4VPException(OID4VPEnumError.PRESENTATION_SUBMISSION_MISSING_DATA,
                  "The value of the definition_id in presentation_submission is not the supported.");
        }
        logger.info("Validated the definition_id of the presentation_submission.");

        JSONArray descriptor_map = presentation_submission.getJSONArray("descriptor_map");
        JSONObject descriptor_map_response = IntStream.range(0, descriptor_map.length())
                .mapToObj(descriptor_map::getJSONObject)
                .filter(jobj -> jobj.getString("id").equals(this.presentationDefinitionInputDescriptorsId))
                .findFirst()
                .orElse(null);

        if (descriptor_map_response == null) {
            logger.error("None of the descriptor_map in the presentation_submission contains information about the requested VP Token.");
            throw new OID4VPException(OID4VPEnumError.PRESENTATION_SUBMISSION_MISSING_DATA,
                  "None of the descriptor_map in the presentation_submission contains information about the requested VP Token.");
        }
        logger.info("Found the descriptor_map in the presentation_submission.");

        if (!descriptor_map_response.getString("format").equals("mso_mdoc")) {
            logger.error("The VP Token format is {}. However, the current implementation only supports vp_token in the format mso_mdoc.",
                  descriptor_map_response.getString("format"));
            throw new OID4VPException(OID4VPEnumError.PRESENTATION_SUBMISSION_MISSING_DATA,
                  "VP Token received is not a mso_mdoc. The current implementation only supports vp_token in the format mso_mdoc.");
        }
        logger.info("Validated that the VP Token is in the supported format: mso_mdoc.");

        return getPathIntValue(descriptor_map_response);
    }

    /**
     * Function that allows to obtain the position from the 'path' value from the  descriptor_map
     * @param descriptor_map_response The JSON Object from the JSON Array
     *                                descriptor_map from where to obtain the path value
     * @return The position presented in the 'path' value in the descriptor_map
     */
    private static int getPathIntValue(JSONObject descriptor_map_response) throws OID4VPException {
        String path = descriptor_map_response.getString("path");

        int pos;
        if (path.equals("$")) {
            pos = 0;
        } else {
            Matcher matcher = Pattern.compile("\\d+").matcher(path);
            if (matcher.find())
                pos = Integer.parseInt(matcher.group());
            else pos = -1;
        }

        if (pos == -1){
            logger.error("The path value was not found in the descriptor_map of the presentation_submission.");
            throw new OID4VPException(OID4VPEnumError.PRESENTATION_SUBMISSION_MISSING_DATA,
                  "The path value was not found in the descriptor_map of the presentation_submission.");
        }

        logger.info("The path {} was retrieved from the descriptor_map of the presentation_submission.", pos);
        return pos;
    }

    /**
     * Function that loads the vp_token from the Verifiable Presentation to the
     * class DeviceResponse from the package id.walt.mdoc.dataretrieval
     */
    private DeviceResponse loadVpTokenToDeviceResponse() {
        String deviceResponse = this.verifiablePresentation.getJSONArray("vp_token").getString(0);
        byte[] decodedBytes = Base64.getUrlDecoder().decode(deviceResponse);
        StringBuilder hexString = new StringBuilder();
        for (byte b : decodedBytes) {
            hexString.append(String.format("%02x", b));
        }
        return DeviceResponse.Companion.fromCBORHex(hexString.toString());
    }

    // [0]: the certificate from the issuer signed
    // [1...]: the Certificate list
    private List<X509Certificate> getAndValidateCertificateFromIssuerAuth(MDoc document) throws CertificateException, OID4VPException {
        COSESign1 issuerAuth = document.getIssuerSigned().getIssuerAuth();
        CertificateFactory factory = CertificateFactory.getInstance("x.509");
        assert issuerAuth != null;
        InputStream in = new ByteArrayInputStream(Objects.requireNonNull(issuerAuth.getX5Chain()));
        X509Certificate cert = (X509Certificate) factory.generateCertificate(in);

        X509Certificate issuerCertificate = this.trustedIssuersCertificate.getTrustIssuersCertificates().get(cert.getIssuerX500Principal().toString());
        if (issuerCertificate == null) {
            logger.error("The issuer certificate of the IssuerAuth of the VP Token is not one of the trusted certificates.");
            throw new OID4VPException(OID4VPEnumError.CERTIFICATE_ISSUER_AUTH_INVALID,
                  "The issuer certificate of the IssuerAuth is not trustworthy.");
        }

        try {
            issuerCertificate.verify(issuerCertificate.getPublicKey());
            issuerCertificate.checkValidity();
        } catch (Exception e){
			logger.error("Failed to validate the issuer certificate. Issuer Certificate: {}. Validaty: Not After = {} Not Before = {}",
                  issuerCertificate.getIssuerX500Principal().getName(), issuerCertificate.getNotAfter().toString(), issuerCertificate.getNotBefore().toString());
            throw new OID4VPException(OID4VPEnumError.CERTIFICATE_ISSUER_AUTH_INVALID, "The certificate of the issuer of the IssuerAuth is not valid.");
        }

        try {
            cert.verify(issuerCertificate.getPublicKey());
            cert.checkValidity();
        }catch (Exception e){
			logger.error("Failed to validate the certificate. Certificate: {}. Validaty: Not After = {} Not Before = {}",
                  cert.getSubjectX500Principal().getName(), cert.getNotAfter().toString(), cert.getNotBefore().toString());
            throw new OID4VPException(OID4VPEnumError.CERTIFICATE_ISSUER_AUTH_INVALID, "The certificate of the IssuerAuth is not valid.");
        }

        List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(cert);
        certificateChain.add(issuerCertificate);
        return certificateChain;
    }

    private SimpleCOSECryptoProvider getSimpleCOSECryptoProvider(X509Certificate certificate,
            List<X509Certificate> certificateChain) {
        COSECryptoProviderKeyInfo keyInfo = new COSECryptoProviderKeyInfo(
                this.keyID, AlgorithmID.ECDSA_256, certificate.getPublicKey(),
                null, Collections.singletonList(certificate), certificateChain);
        return new SimpleCOSECryptoProvider(Collections.singletonList(keyInfo));
    }

    private static void validateValidityInfoElements(MDoc document, ValidityInfo validityInfo, java.time.Instant notBefore, java.time.Instant notAfter) throws VerifiablePresentationVerificationException {
        if (!document.verifyValidity()) { // This function verifies the Validity, based on validity info given in the MSO.
            throw new VerifiablePresentationVerificationException(OID4VPEnumError.VALIDITY_INFO_INVALID,
                    "Failed the ValidityInfo verification step: the ValidFrom or the ValidUntil from the IssuerAuth is later than the current time.",
                    VerifiablePresentationVerificationException.DEFAULT);
        }

        Instant validity_info_signed = validityInfo.getSigned().getValue();
        Instant certNotBefore = new Instant(notBefore);
        Instant certNotAfter = new Instant(notAfter);
        if (validity_info_signed.compareTo(certNotAfter) > 0 || validity_info_signed.compareTo(certNotBefore) < 0)
            throw new VerifiablePresentationVerificationException(OID4VPEnumError.VALIDITY_INFO_INVALID,
                    "Failed the ValidityInfo verification step: the Signed in the IssuerAuth is not valid.", VerifiablePresentationVerificationException.DEFAULT);
    }

    public MDoc loadAndVerifyDocumentForVP() throws OID4VPException {
        try {
            // Validate the Presentation Submission and get the Path value from the descriptor_map
            int pos = validatePresentationSubmission();
            logger.info("Retrieved the position of the VP Token. Position: {}.", pos);

            // Load VP Token from the Verifier Message
            DeviceResponse vpToken = loadVpTokenToDeviceResponse();

            logger.info("Loaded the VP Token from the Verifier Response.");

            // Verify that the status in the vpToken is equal "success"
            if (vpToken.getStatus().getValue().intValue() != 0) {
                logger.error("The value of status in the vp_token is {} and invalid.", vpToken.getStatus().getValue().intValue());
                throw new OID4VPException(OID4VPEnumError.STATUS_VP_TOKEN_INVALID,
                      "The vp_token's status is not equal to a successful status (0).");
            }
            logger.info("Validated the value of status in the vp_token.");

            // retrieve the document in the position
            MDoc document = vpToken.getDocuments().get(pos);
            logger.info("Retrieved the document from the vp_token in the position {}.", pos);

            // Validate Certificate from the MSO header:
            SimpleCOSECryptoProvider provider;
            X509Certificate certificateFromIssuerAuth;
            try {
                List<X509Certificate> certificateList = getAndValidateCertificateFromIssuerAuth(document);
                certificateFromIssuerAuth = certificateList.get(0);
                List<X509Certificate> certificateChain = certificateList.subList(1, certificateList.size());
                provider = getSimpleCOSECryptoProvider(certificateFromIssuerAuth, certificateChain);
            } catch (CertificateException e) {
                logger.error("Failed to validate the certificate in the IssuerAuth. Error: {}", e.getMessage());
                throw new OID4VPException(OID4VPEnumError.CERTIFICATE_ISSUER_AUTH_INVALID, "Unexpected Error when trying to validate the certificate in the IssuerAuth.");
            }
            logger.info("Validated the certificate in the IssuerAuth.");

            if (!document.verifyCertificate(provider, this.keyID))
                throw new VerifiablePresentationVerificationException(OID4VPEnumError.CERTIFICATE_ISSUER_AUTH_INVALID,
                      "Certificate in issuerAuth is not valid.", VerifiablePresentationVerificationException.DEFAULT);

            // Verify the ValidityInfo:
            /*MSO mso = document.getMSO();
            validateValidityInfoElements(document, mso.getValidityInfo(), certificateFromIssuerAuth.getNotBefore().toInstant(), certificateFromIssuerAuth.getNotAfter().toInstant())*/

            // Verify the "DocType" in MSO == "DocType" in Documents
            /*if (!document.verifyDocType())
                throw new VerifiablePresentationVerificationException(OID4VPEnumError.DocTypeMSODifferentFromDocuments,
                      "The DocType in the MSO is not equal to the DocType in documents.",
                      VerifiablePresentationVerificationException.Default);

            // Verify if the digest of issuer signed items are equal to the digest in the MSO
            if (!document.verifyIssuerSignedItems())
                throw new VerifiablePresentationVerificationException(OID4VPEnumError.IntegrityVPTokenNotVerified,
                      "The digest of the IssuerSignedItems are not equal to the digests in MSO.",
                      VerifiablePresentationVerificationException.Integrity);

            // Verify the Digital Signature in the Issuer Auth
            if (!document.verifySignature(provider, this.keyID))
                throw new VerifiablePresentationVerificationException(OID4VPEnumError.SignatureIssuerAuthInvalid,
                        "The IssuerAuth Signature is not valid.", VerifiablePresentationVerificationException.Signature);
             */

            return document;
        }
        catch (OID4VPException e){
            throw e;
        }
        catch (JSONException e){
			logger.error("JSONException found. Error: {}", e.getMessage());
            throw new OID4VPException(OID4VPEnumError.UNEXPECTED_ERROR, "The JSON string contains unexpected errors ("+e.getMessage()+").");
        }
        catch (Exception e){
			logger.error("{} : {}", OID4VPEnumError.UNEXPECTED_ERROR.getFormattedMessage(), e.getMessage());
            throw new OID4VPException(OID4VPEnumError.UNEXPECTED_ERROR, e.getMessage());
        }
    }
}
