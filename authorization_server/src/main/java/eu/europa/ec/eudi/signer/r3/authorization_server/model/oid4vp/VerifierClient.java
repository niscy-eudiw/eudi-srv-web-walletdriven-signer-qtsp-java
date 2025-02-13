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

import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPException;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.VerifierCreatedVariable;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.VerifierCreatedVariables;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.VerifierConfig;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Component responsible to make requests to an OpenID4VP Verifier
 * And create the links necessary to redirect the user to the Verifier
 */
@Component
public class VerifierClient {
    public static final String PresentationDefinitionId = "32f54163-7166-48f1-93d8-ff217bdb0653";
    public static final String PresentationDefinitionInputDescriptorsId = "eu.europa.ec.eudi.pid.1";
    private static final Logger log = LoggerFactory.getLogger(VerifierClient.class);
    private final VerifierConfig verifierProperties;
    private final VerifierCreatedVariables verifierVariables;

    public VerifierClient(VerifierConfig verifierProperties) {
        this.verifierProperties = verifierProperties;
        this.verifierVariables = new VerifierCreatedVariables();
    }

    /**
     * Function that allows to make a Presentation Request to the OpenID for Verifiable Presentations Verifier,
     * following the OpenID for Verifiable Presentations - draft 20.
     * @param userId an identifier of the user that made the request
     * @param currentServiceUrl the url of the current service
     * @return the deep link that redirects the client app to the EUDI Wallet
     */
    public String initSameDeviceTransactionToVerifier(String userId, String currentServiceUrl) throws Exception {
        log.info("Starting Presentation Request and redirection link generation for the user {}", userId);
        String nonce = getNonce();

        // makes the http Presentation Request:
        JSONObject responseFromVerifier;
        try {
            responseFromVerifier = httpRequestToInitPresentation(userId, currentServiceUrl, nonce, false);
        } catch (Exception e) {
            throw new Exception(OID4VPEnumError.FailedConnectionToVerifier.getFormattedMessage());
        }
        log.info("Successfully completed the HTTP Post Presentation Request for authentication of the user {}", userId);

        // Validates if the values required are present in the JSON Object Response:
        Set<String> keys = responseFromVerifier.keySet();
        if (!keys.contains("request_uri") || !keys.contains("client_id") || !keys.contains("presentation_id"))
            throw new Exception(OID4VPEnumError.MissingDataInResponseVerifier.getFormattedMessage());
        String request_uri = responseFromVerifier.getString("request_uri");
        String encoded_request_uri = URLEncoder.encode(request_uri, StandardCharsets.UTF_8);
        String client_id = responseFromVerifier.getString("client_id");
        if(!client_id.equals(this.verifierProperties.getAddress()))
            throw new Exception(OID4VPEnumError.UnexpectedError.getFormattedMessage());
        String presentation_id = responseFromVerifier.getString("presentation_id");

        // Saves the values required associated to later retrieve the VP Token from the Verifier:
        this.verifierVariables.addUsersVerifierCreatedVariable(userId, nonce, presentation_id);

        // Generates a link to the Wallet, to where the client app will be redirected:
        String linkToWallet = getLinkToWallet(encoded_request_uri, client_id);
        log.info("Generated link to the Wallet for authentication of the user {}", userId);
        return linkToWallet;
    }

    public String initCrossDeviceTransactionToVerifier(String userId, String currentServiceUrl) throws Exception {
        log.info("Starting Presentation Request and redirection link generation for the user {}", userId);
        String nonce = getNonce();

        // makes the http Presentation Request:
        JSONObject responseFromVerifier;
        try {
            responseFromVerifier = httpRequestToInitPresentation(userId, currentServiceUrl, nonce, true);
        } catch (Exception e) {
            throw new Exception(OID4VPEnumError.FailedConnectionToVerifier.getFormattedMessage());
        }
        log.info("Successfully completed the HTTP Post Presentation Request for authentication of the user {}", userId);

        // Validates if the values required are present in the JSON Object Response:
        Set<String> keys = responseFromVerifier.keySet();
        if (!keys.contains("request_uri") || !keys.contains("client_id") || !keys.contains("presentation_id"))
            throw new Exception(OID4VPEnumError.MissingDataInResponseVerifier.getFormattedMessage());
        String request_uri = responseFromVerifier.getString("request_uri");
        String encoded_request_uri = URLEncoder.encode(request_uri, StandardCharsets.UTF_8);
        String client_id = responseFromVerifier.getString("client_id");
        if(!client_id.equals(this.verifierProperties.getAddress()))
            throw new Exception(OID4VPEnumError.UnexpectedError.getFormattedMessage());
        String presentation_id = responseFromVerifier.getString("presentation_id");

        // Saves the values required associated to later retrieve the VP Token from the Verifier:
        this.verifierVariables.addUsersVerifierCreatedVariable(userId, nonce, presentation_id);

        // Generates a link to the Wallet, to where the client app will be redirected:
        String linkToWallet = getLinkToWallet(encoded_request_uri, client_id);
        log.info("Generated link to the Wallet for authentication of the user {}", userId);
        return linkToWallet;
    }

    private String getNonce() throws Exception {
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        return Base64.getUrlEncoder().encodeToString(result);
    }

    private JSONObject httpRequestToInitPresentation(String userId, String serviceUrl, String nonce, boolean isCrossDevice) throws Exception {
        Map<String, String> headers = getHeaders();

        String bodyMessage;
        if(isCrossDevice) bodyMessage = getCrossDeviceMessage(nonce);
        else bodyMessage = getSameDeviceMessage(userId, serviceUrl, nonce);

        // makes a request to the verifier
        HttpResponse response;
        try {
            response = WebUtils.httpPostRequest(verifierProperties.getUrl(), headers, bodyMessage);
        } catch (Exception e) {
            log.error("An error occurred when trying to connect to the Verifier. {}", e.getMessage());
            throw new Exception("An error occurred when trying to connect to the Verifier");
        }

        // validates if the http request was successful
        if (response.getStatusLine().getStatusCode() != 200) {
            String error = WebUtils.convertStreamToString(response.getEntity().getContent());
            int statusCode = response.getStatusLine().getStatusCode();

            // Remove Special Characters
            String noControlChars = error.replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");

            // escape HTML Tags
            String escapedError = StringEscapeUtils.escapeHtml4(noControlChars);

            // Validate that the message only contains alphanumeric characters and basic punctuation
            String validationPattern = "^[a-zA-Z0-9.,:;\\-?!\\s]+$";
            if (!escapedError.matches(validationPattern)) {
                escapedError = "Invalid error message content";
            }

            log.error("[Error {}] HTTP Post request to Verifier was not successful." +
                  " Error Message: {} ", statusCode, escapedError);
            throw new Exception("[Error "+statusCode+"] HTTP Post request to Verifier was not successful.");
        }

        HttpEntity entity = response.getEntity();
        if (entity == null) {
            log.error("Http Post response from the presentation request is empty.");
            throw new Exception("Http Post response from the presentation request is empty.");
        }

        String result = WebUtils.convertStreamToString(entity.getContent());
        JSONObject responseVerifier;
        try{
            responseVerifier =  new JSONObject(result);
        }
        catch (JSONException e){
            log.error("The response of the presentation request from the Verifier doesn't contain a correctly formatted JSON string.");
            throw new Exception("The response of the presentation request from the Verifier doesn't contain a correctly formatted JSON string.");
        }
        return responseVerifier;
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        return headers;
    }

    private JSONObject getPresentationDefinitionJSON(){
        String presentationDefinition = "{" +
              "'id': '32f54163-7166-48f1-93d8-ff217bdb0653'," +
              "'input_descriptors': [{" +
              "'id': '"+PresentationDefinitionInputDescriptorsId+"'," +
              "'name': 'EUDI PID'," +
              "'purpose': 'We need to verify your identity'," +
              "'format': {'mso_mdoc': {" +
              "'alg': ['ES256', 'ES384', 'ES512', 'EdDSA'] } }," +
              "'constraints': {" +
              "'fields': [" +
              "{'path': [\"$['"+PresentationDefinitionInputDescriptorsId+"']['family_name']\"], 'intent_to_retain': true}," +
              "{\"path\": [\"$['"+PresentationDefinitionInputDescriptorsId+"']['given_name']\"],  \"intent_to_retain\": true}," +
              "{\"path\": [\"$['"+PresentationDefinitionInputDescriptorsId+"']['birth_date']\"],  \"intent_to_retain\": true}," +
              "{\"path\": [\"$['"+PresentationDefinitionInputDescriptorsId+"']['age_over_18']\"], \"intent_to_retain\": false}," +
              "{\"path\": [\"$['"+PresentationDefinitionInputDescriptorsId+"']['issuing_authority']\"], \"intent_to_retain\": true}," +
              "{\"path\": [\"$['"+PresentationDefinitionInputDescriptorsId+"']['issuing_country']\"], \"intent_to_retain\": true}" +
              "]}}]}";
		return new JSONObject(presentationDefinition);
    }

    private List<String> getTransactionData(String credentialID){
        List<String> transaction_data = new ArrayList<>();

        JSONObject transaction_data_object = new JSONObject();
        transaction_data_object.put("type", "qes_authorization");

        List<String> credentials_ids = new ArrayList<>();
        credentials_ids.add(PresentationDefinitionInputDescriptorsId);
        transaction_data_object.put("credentials_ids", credentials_ids);

        transaction_data_object.put("credentialID", credentialID);
        transaction_data_object.put("signatureQualifier", "");

        JSONArray documentDigests = new JSONArray();
        JSONObject documentDigestSingle = new JSONObject();
        documentDigestSingle.put("label", "");
        documentDigestSingle.put("hash", "");
        documentDigestSingle.put("hashAlgorithmOID", "");
        documentDigests.put(documentDigestSingle);
        transaction_data_object.put("documentDigests", documentDigests);

        transaction_data_object.put("processID", "");


        String transaction_data_string_base64 = Base64.getEncoder().encodeToString(transaction_data_object.toString().getBytes());
        transaction_data.add(transaction_data_string_base64);

        return transaction_data;
    }


    private String getSameDeviceMessage(String userId, String serviceUrl, String nonce) {
        JSONObject presentationDefinitionJsonObject = getPresentationDefinitionJSON();
        String redirectUri = serviceUrl+"/oid4vp/callback?session_id="+userId+"&response_code={RESPONSE_CODE}";

        // Set JSON Body
        JSONObject jsonBodyToInitPresentation = new JSONObject();
        jsonBodyToInitPresentation.put("type", "vp_token");
        jsonBodyToInitPresentation.put("nonce", nonce);
        jsonBodyToInitPresentation.put("presentation_definition", presentationDefinitionJsonObject);
        jsonBodyToInitPresentation.put("wallet_response_redirect_uri_template", redirectUri);
        return jsonBodyToInitPresentation.toString();
    }

    private String getCrossDeviceMessage(String nonce) {
        JSONObject presentationDefinitionJsonObject = getPresentationDefinitionJSON();

        // Set JSON Body
        JSONObject jsonBodyToInitPresentation = new JSONObject();
        jsonBodyToInitPresentation.put("type", "vp_token");
        jsonBodyToInitPresentation.put("nonce", nonce);
        jsonBodyToInitPresentation.put("presentation_definition", presentationDefinitionJsonObject);
        return jsonBodyToInitPresentation.toString();
    }

    private String getLinkToWallet(String request_uri, String client_id) {
        return "eudi-openid4vp://" + verifierProperties.getAddress() + "?client_id=" +
                client_id + "&request_uri=" + request_uri;
    }

    /**
     * Function that allows to retrieve the VP Token from the Verifier
     * @param userId an identifier of the user that made the request
     * @param code the code returned by the verifier and required to retrieve the VP Token
     * @return a json formatted string with the vp token
     */
    public String getVPTokenFromVerifier(String userId, String code) throws OID4VPException {
        log.info("Starting to retrieve the VP Token from the Verifier to authenticate the user {}...", userId);

        VerifierCreatedVariable variables = verifierVariables.getUsersVerifierCreatedVariable(userId);
        if (variables == null) {
            log.error("Failed to retrieve the required local variables to complete the authentication.");
            throw new OID4VPException(OID4VPEnumError.UnexpectedError, "Something went wrong on our end during sign-in. Please try again in a few moments.");
        }
        log.info("Retrieved the required local variables to complete the authentication.");

        log.info("Current Verifier Variables State: {}", verifierVariables);
        log.debug("User: {} & Nonce: {} & Presentation_id: {}", userId, variables.getNonce(), variables.getPresentation_id());

        Map<String, String> headers = getHeaders();
        String url = getUrlToRetrieveVPTokenWithResponseCode(variables.getPresentation_id(), variables.getNonce(), code);
        log.info("Obtained the link to retrieve the VP Token from the Verifier.");
        log.debug("Link to retrieve the VP Token: {}", url);

        WebUtils.StatusAndMessage response;
        try {
            response = WebUtils.httpGetRequests(url, headers);
        } catch (Exception e) {
            log.error("Failed to retrieve the VP Token from the Verifier. Error: {}", e.getMessage());
            throw new OID4VPException(OID4VPEnumError.FailedConnectionToVerifier, "We couldn’t connect to the OID4VP Verifier server and authentication failed.");
        }

        if(response.getStatusCode() == 200){
            if(response.getMessage() == null || Objects.equals(response.getMessage(), "")){
                String errorMessage = "It was not possible to retrieve a VP Token from the OID4VP Verifier Backend.";
                log.error("{} The message retrieved from the OID4VP Verifier Backend is empty.", errorMessage);
                throw new OID4VPException(OID4VPEnumError.MissingDataInResponseVerifier,
                      "The server expected to receive a well-formatted VP Token from the OID4VP Verifier Backend. However, the response from the OID4VP Verifier Backend is empty.");
            }
            log.info("Retrieved the VP Token from the Verifier to authenticate the user {}.", userId);
            return response.getMessage();
        }
        else{
			log.error("Failed to connect with Verifier and retrieve the VP Token. Status Code: {}. Error: {}", response.getStatusCode(), response.getMessage());
            throw new OID4VPException(OID4VPEnumError.FailedConnectionToVerifier, "The OID4VP Verifier service is currently unavailable.");
        }
    }

    public String getVPTokenFromVerifierRecursive(String user) throws OID4VPException, InterruptedException {
        log.info("Starting to retrieve the VP Token from the Verifier to authenticate the user {}...", user);

        VerifierCreatedVariable variables = verifierVariables.getUsersVerifierCreatedVariable(user);
        if (variables == null) {
            log.error("Failed to retrieve the required local variables to complete the authentication.");
            throw new OID4VPException(OID4VPEnumError.UnexpectedError, "Something went wrong on our end during sign-in. Please try again in a few moments.");
        }
        log.info("Retrieved the required local variables to complete the authentication.");

        log.info("Current Verifier Variables State: {}", verifierVariables);
        log.debug("User: {} & Nonce: {} & Presentation_id: {}", user, variables.getNonce(), variables.getPresentation_id());

        Map<String, String> headers = getHeaders();
        String url = getUrlToRetrieveVPToken(variables.getPresentation_id(), variables.getNonce());
        log.info("Obtained the link to retrieve the VP Token from the Verifier.");
        log.debug("Link to retrieve the VP Token: {}", url);

        String message = null;
        int responseCode = 400;
        long startTime = System.currentTimeMillis();

        while (responseCode != 200 && (System.currentTimeMillis() - startTime) < 60000) { // enquanto que não teve sucesso ou ainda não passou 1 min...
            WebUtils.StatusAndMessage response;
            try {
                response = WebUtils.httpGetRequests(url, headers);
            } catch (Exception e) {
                log.error("Failed to retrieve the VP Token from the Verifier. Error: {}", e.getMessage());
                throw new OID4VPException(OID4VPEnumError.FailedConnectionToVerifier, "We could not connect to the OID4VP Verifier server and authentication failed.");
            }

            if (response.getStatusCode() == 404 || response.getStatusCode() == 500) { // if unable to connect or exception...
                log.error("Failed to connect with Verifier and retrieve the VP Token. Status Code: {}. Error: {}", response.getStatusCode(), response.getMessage());
                throw new OID4VPException(OID4VPEnumError.FailedConnectionToVerifier, "The OID4VP Verifier service is currently unavailable.");
            }
            else if (response.getStatusCode() == 200) { // if succcess...
                responseCode = 200;
                if(response.getMessage() == null || Objects.equals(response.getMessage(), "")){ // if message is empty throw exception...
                    String errorMessage = "It was not possible to retrieve a VP Token from the OID4VP Verifier Backend.";
                    log.error("{} The message retrieved from the OID4VP Verifier Backend is empty.", errorMessage);
                    throw new OID4VPException(OID4VPEnumError.MissingDataInResponseVerifier, "The server expected to receive a well-formatted VP Token from the OID4VP Verifier Backend. However, the response from the OID4VP Verifier Backend is empty.");
                }
                log.info("Retrieved the VP Token from the Verifier to authenticate the user {}.", user);
                message = response.getMessage();
            } else
                TimeUnit.SECONDS.sleep(1);
        }

        if (responseCode == 400 && (System.currentTimeMillis() - startTime) >= 60000){ // if unsuccessful in period of time...
            log.error("Failed to retrieve the VP Token. Error: response code 400 or operation timed out.");
            throw new OID4VPException(OID4VPEnumError.ConnectionVerifierTimedOut, "The user should scan the QrCode and share the PID information in 1 min.");
        }
        return message;
    }

    private String getUrlToRetrieveVPTokenWithResponseCode(String presentation_id, String nonce, String code) {
        return verifierProperties.getUrl() + "/" + presentation_id + "?nonce=" + nonce + "&response_code=" + code;
    }

    private String getUrlToRetrieveVPToken(String presentation_id, String nonce) {
        return verifierProperties.getUrl() + "/" + presentation_id + "?nonce=" + nonce;
    }
}
