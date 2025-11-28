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
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.VerifierCreatedVariables;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.VerifierCreatedVariables.VerifierCreatedVariable;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.OID4VPEnumError;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.VerifierConfig;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
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
    public static final String PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID = "eu.europa.ec.eudi.pid.1";
	private static final Logger log = LoggerFactory.getLogger(VerifierClient.class);
    private final VerifierConfig verifierProperties;
    private final VerifierCreatedVariables verifierVariables;

    public VerifierClient(VerifierConfig verifierProperties) {
        this.verifierProperties = verifierProperties;
        this.verifierVariables = new VerifierCreatedVariables();
    }

    public String initSameDeviceTransactionToVerifier(String userId, String currentServiceUrl, JSONArray transaction_data) throws Exception {
        return initTransactionToVerifier(userId, currentServiceUrl, false, transaction_data);
    }

    public String initCrossDeviceTransactionToVerifier(String userId, String currentServiceUrl, JSONArray transaction_data) throws Exception {
        return initTransactionToVerifier(userId, currentServiceUrl, true, transaction_data);
    }

    private String initTransactionToVerifier(String userId, String currentServiceUrl, boolean isCrossDevice, JSONArray transaction_data) throws Exception {
        log.info("Starting Presentation Request and redirection link generation for the user {}", userId);
        String nonce = getNonce();

        // makes the http Presentation Request:
        JSONObject responseFromVerifier;
        try {
            responseFromVerifier = httpRequestToInitPresentation(userId, currentServiceUrl, nonce, isCrossDevice, transaction_data);
        } catch (Exception e) {
            throw new Exception(OID4VPEnumError.FAILED_CONNECTION_TO_VERIFIER.getFormattedMessage());
        }
        log.info("Successfully completed the HTTP Post Presentation Request for authentication of the user {}", userId);

        // Validates if the values required are present in the JSON Object Response:
        Set<String> keys = responseFromVerifier.keySet();
		String request_uri1 = "request_uri";
		if (!keys.contains(request_uri1)){
            log.error("Missing 'request_uri' from InitTransaction Response");
            throw new Exception(OID4VPEnumError.MISSING_DATA_IN_RESPONSE_VERIFIER.getFormattedMessage());
        }
		String client_id1 = "client_id";
		if(!keys.contains(client_id1)){
            log.error("Missing 'client_id' from InitTransaction Response");
            throw new Exception(OID4VPEnumError.MISSING_DATA_IN_RESPONSE_VERIFIER.getFormattedMessage());
        }
		String transaction_id = "transaction_id";
		if(!keys.contains(transaction_id)){
            log.error("Missing 'transaction_id' from InitTransaction Response");
            throw new Exception(OID4VPEnumError.MISSING_DATA_IN_RESPONSE_VERIFIER.getFormattedMessage());
        }
        log.info("All keys are present.");

        String request_uri = responseFromVerifier.getString(request_uri1);
        String encoded_request_uri = URLEncoder.encode(request_uri, StandardCharsets.UTF_8);
		log.info("Encoded Request URI: {}", encoded_request_uri);
        String client_id = responseFromVerifier.getString(client_id1);
		log.info("Client Id: {}", client_id);
        /*if(!client_id.contains(this.verifierProperties.getClientId())) {
            log.error("Client Id Received different from Client Id expected");
            throw new Exception(OID4VPEnumError.UNEXPECTED_ERROR.getFormattedMessage());
        }*/
        String presentation_id = responseFromVerifier.getString(transaction_id);
		log.info("Transaction Id: {}", presentation_id);

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

    private JSONObject httpRequestToInitPresentation(String userId, String serviceUrl, String nonce, boolean isCrossDevice, JSONArray transaction_data) throws Exception {
        Map<String, String> headers = getHeaders();

        String bodyMessage;

        log.info("Transaction_data: {}", transaction_data);
        if(isCrossDevice) bodyMessage = getCrossDeviceMessage(nonce, transaction_data);
        else bodyMessage = getSameDeviceMessage(userId, serviceUrl, nonce, transaction_data);

        log.info("Message to Verifier: {}", bodyMessage);

        // makes a request to the verifier
        HttpResponse response;
        try {
            response = WebUtils.httpPostRequest(verifierProperties.getPresentationUrl(), headers, bodyMessage);
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

    private JSONObject getDCQLQueryMSOMDoc(){
        String dcqlQuery = "{" +
              "'credentials': [" +
                "{" +
                    "'id': 'query_0'," +
                    "'format': 'mso_mdoc'," +
                    "'meta': {'doctype_value': '"+PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"'}," +
                    "'claims': [" +
                        "{" +
                        "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'family_name']," +
                        "'intent_to_retain': false" +
                        "}," +
                        "{" +
                        "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'given_name']," +
                        "'intent_to_retain': false" +
                        "}," +
                        "{" +
                        "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'birth_date']," +
                        "'intent_to_retain': false" +
                        "}," +
                        "{" +
                        "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'issuing_authority']," +
                        "'intent_to_retain': false" +
                        "}," +
                        "{" +
                        "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'issuing_country']," +
                        "'intent_to_retain': false" +
                        "}" +
                    "]" +
                "}" +
              "]" +
        "}";
        return new JSONObject(dcqlQuery);
    }

    private JSONObject getDCQLQuerySDJWT(){
        String dcqlQuery = "{" +
              "'credentials': [" +
              "{" +
              "'id': 'query_0'," +
              "'format': 'dc+sd-jwt'," +
              "'meta': {'vct_values': ['urn:eudi:pid:1']}," +
              "'claims': [" +
              "{'path': ['family_name']}," +
              "{'path': ['given_name']}," +
              "{'path': ['birthdate']}," +
              "{'path': ['issuing_authority']}," +
              "{'path': ['issuing_country']}" +
              "]" +
              "}" +
              "]" +
              "}";
        return new JSONObject(dcqlQuery);
    }

    private String getSameDeviceMessage(String userId, String serviceUrl, String nonce, JSONArray transaction_data) {
        JSONObject dcqlQueryJSON = getDCQLQuerySDJWT();
        String redirectUri = serviceUrl+"/oid4vp/callback?session_id="+userId+"&response_code={RESPONSE_CODE}";

        // Set JSON Body
        JSONObject jsonBodyToInitPresentation = new JSONObject();
        jsonBodyToInitPresentation.put("type", "vp_token");
        jsonBodyToInitPresentation.put("nonce", nonce);
        jsonBodyToInitPresentation.put("dcql_query", dcqlQueryJSON);
        jsonBodyToInitPresentation.put("wallet_response_redirect_uri_template", redirectUri);
        if(transaction_data != null)
            jsonBodyToInitPresentation.put("transaction_data", transaction_data);
        return jsonBodyToInitPresentation.toString();
    }

    private String getCrossDeviceMessage(String nonce, JSONArray transaction_data) {
        JSONObject dcqlQueryJSON = getDCQLQuerySDJWT();

        // Set JSON Body
        JSONObject jsonBodyToInitPresentation = new JSONObject();
        jsonBodyToInitPresentation.put("type", "vp_token");
        jsonBodyToInitPresentation.put("nonce", nonce);
        jsonBodyToInitPresentation.put("dcql_query", dcqlQueryJSON);
        jsonBodyToInitPresentation.put("request_uri_method", "post");
        if(transaction_data != null)
            jsonBodyToInitPresentation.put("transaction_data", transaction_data);
        return jsonBodyToInitPresentation.toString();
    }

    private String getLinkToWallet(String request_uri, String client_id) {
        return "eudi-openid4vp://" + verifierProperties.getAddress() + "?client_id=" +
                client_id + "&request_uri=" + request_uri;
    }

    private VerifierCreatedVariable retrieveAndRemoveVerifierVariables(String userId) throws OID4VPException {
        VerifierCreatedVariable variables = verifierVariables.getAndRemoveUsersVerifierCreatedVariable(userId);
        if (variables == null) {
            log.error("Failed to retrieve the required local variables to complete the authentication.");
            throw new OID4VPException(OID4VPEnumError.UNEXPECTED_ERROR, "Something went wrong on our end during sign-in. Please try again in a few moments.");
        }
        log.info("Retrieved the required local variables to complete the authentication.");
        log.info("Current Verifier Variables State: {}", verifierVariables);
        return variables;
    }

    private VerifierCreatedVariable retrieveVerifierVariables(String userId) throws OID4VPException {
        VerifierCreatedVariable variables = verifierVariables.getUsersVerifierCreatedVariable(userId);
        if (variables == null) {
            log.error("Failed to retrieve the required local variables to complete the authentication.");
            throw new OID4VPException(OID4VPEnumError.UNEXPECTED_ERROR, "Something went wrong on our end during sign-in. Please try again in a few moments.");
        }
        log.info("Retrieved the required local variables to complete the authentication.");
        log.info("Current Verifier Variables State: {}", verifierVariables);
        return variables;
    }

    private WebUtils.StatusAndMessage getVerifierResponse(String url, Map<String, String> headers) throws OID4VPException {
        try {
            return WebUtils.httpGetRequests(url, headers);
        } catch (Exception e) {
            log.error("Failed to retrieve the VP Token from the Verifier. Error: {}", e.getMessage());
            throw new OID4VPException(OID4VPEnumError.FAILED_CONNECTION_TO_VERIFIER, "We could not connect to the OID4VP Verifier server and authentication failed."
            );
        }
    }

    private String extractVPTokenOrThrow(WebUtils.StatusAndMessage response) throws OID4VPException {
        String message = response.getMessage();
        if (message == null || message.trim().isEmpty()) {
            log.error("The message retrieved from the OID4VP Verifier Backend is empty.");
            throw new OID4VPException(OID4VPEnumError.MISSING_DATA_IN_RESPONSE_VERIFIER, "The server expected to receive a well-formatted VP Token from the OID4VP Verifier Backend. However, the response is empty."
            );
        }
        return message;
    }

    /**
     * Function that allows to retrieve the VP Token from the Verifier
     * @param userId an identifier of the user that made the request
     * @param code the code returned by the verifier and required to retrieve the VP Token
     * @return a json formatted string with the vp token
     */
    public String getVPTokenFromVerifier(String userId, String code) throws OID4VPException {
        log.info("Starting to retrieve the VP Token from the Verifier to authenticate the user {}...", userId);

        VerifierCreatedVariable variables = retrieveAndRemoveVerifierVariables(userId);

        Map<String, String> headers = getHeaders();
        String url = getUrlToRetrieveVPTokenWithResponseCode(variables.getTransaction_id(), variables.getNonce(), code);
        log.info("Obtained the link to retrieve the VP Token from the Verifier.");
        log.debug("Link to retrieve the VP Token: {}", url);

        WebUtils.StatusAndMessage response = getVerifierResponse(url, headers);

        if(response.getStatusCode() == 200) {
            String message = extractVPTokenOrThrow(response);
            log.info("Retrieved the VP Token from the Verifier.");
            return message;
        }
        else{
			log.error("Failed to connect with Verifier and retrieve the VP Token. Status Code: {}. Error: {}", response.getStatusCode(), response.getMessage());
            throw new OID4VPException(OID4VPEnumError.FAILED_CONNECTION_TO_VERIFIER, "The OID4VP Verifier service is currently unavailable.");
        }
    }

    public String getVPTokenFromVerifierRecursive(String user) throws OID4VPException, InterruptedException {
        log.info("Starting to recursively retrieve the VP Token from the Verifier to authenticate the user {}...", user);

        VerifierCreatedVariable variables = retrieveAndRemoveVerifierVariables(user);

        Map<String, String> headers = getHeaders();
        String url = getUrlToRetrieveVPToken(variables.getTransaction_id(), variables.getNonce());
        log.info("Obtained the link to retrieve the VP Token from the Verifier.");
        log.debug("Link to retrieve the VP Token: {}", url);

        long startTime = System.currentTimeMillis();
        while ((System.currentTimeMillis() - startTime) < 60000) {
            WebUtils.StatusAndMessage response = getVerifierResponse(url, headers);
            int status = response.getStatusCode();

            if (status == 200) {
                String message = extractVPTokenOrThrow(response);
                log.info("Retrieved the VP Token from the Verifier.");
                return message;
            }
            else if (status == 404 || status == 500) { // if unable to connect or exception...
                log.error("Failed to connect with Verifier and retrieve the VP Token. Status Code: {}. Error: {}", status, response.getMessage());
                throw new OID4VPException(OID4VPEnumError.FAILED_CONNECTION_TO_VERIFIER, "The OID4VP Verifier service is currently unavailable.");
            }
            TimeUnit.SECONDS.sleep(1);
        }
        log.error("Failed to retrieve the VP Token. Error: response code 400 or operation timed out.");
        throw new OID4VPException(OID4VPEnumError.CONNECTION_VERIFIER_TIMED_OUT, "The user should scan the QrCode and share the PID information in 1 min.");
    }

    private String getUrlToRetrieveVPTokenWithResponseCode(String presentation_id, String nonce, String code) {
        return verifierProperties.getPresentationUrl() + "/" + presentation_id + "?nonce=" + nonce + "&response_code=" + code;
    }

    private String getUrlToRetrieveVPToken(String presentation_id, String nonce) {
        return verifierProperties.getPresentationUrl() + "/" + presentation_id + "?nonce=" + nonce;
    }

    public JSONObject validateMSOMDocDeviceResponse(String MSO_MDoc_Device_Response) throws OID4VPException{
        Map<String, String> headers = new HashMap<>();
        headers.put("accept", "application/json");
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        String body = "device_response="+MSO_MDoc_Device_Response;

        HttpResponse response;
        try{
            response = WebUtils.httpPostRequest(this.verifierProperties.getValidationUrl(), headers, body);
        }
        catch (Exception e){
            log.error("An error occurred when trying to make a request to the Verifier. {}", e.getMessage());
            throw new OID4VPException(OID4VPEnumError.FAILED_CONNECTION_TO_VERIFIER, "It wasn't possible to validate the Verifier Response.");
        }

		if(response.getStatusLine().getStatusCode() == 200){
            log.info("Successfully validated verifier response (Status Code: 200).");

            JSONArray responseVerifier;
            try {
                String result = WebUtils.convertStreamToString(response.getEntity().getContent());
                responseVerifier = new JSONArray(result);
                log.info("Parsed the validation response.");
            }
            catch (IOException e){
                log.error("It was impossible to retrieve the content from the validation request to the OID4VP Verifier.");
                throw new OID4VPException(OID4VPEnumError.UNEXPECTED_ERROR, "It was impossible to retrieve the validation response from the Verifier.");
            }
            catch (JSONException e){
                log.error("It was impossible to parse validation response as a JSON Array.");
                throw new OID4VPException(OID4VPEnumError.RESPONSE_VERIFIER_WITH_INVALID_FORMAT, "The Verifier's validation response is not a valid JSON Array.");
            }

            for(int i = 0; i < responseVerifier.length(); i++){
                JSONObject jsonObject = responseVerifier.getJSONObject(i);
                if (!jsonObject.has("docType")){
                    log.error("Expected 'docType' missing from the Verifier's Validation Endpoint response.");
                    throw new OID4VPException(OID4VPEnumError.MISSING_DATA_IN_RESPONSE_VERIFIER, "the validation of the OID4VP Verifier response failed because expected 'doctype' parameter is missing.");
                }
                if(jsonObject.get("docType").equals(PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID)){
                    log.info("Received attributes of the requested doctype {}", PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID);
                    JSONObject attributes = jsonObject.getJSONObject("attributes").getJSONObject(PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID);
                    log.info("Retrieved attributes as a JSONObject.");
                    return attributes;
                }
            }
            log.error("Attributes of the requested 'doctype' not found in the validation response.");
            throw new OID4VPException(OID4VPEnumError.MISSING_DATA_IN_RESPONSE_VERIFIER, "the validation of the OID4VP Verifier response failed because expected 'attributes' parameter is missing.");
        }
        else{
            try {
                HttpEntity entity = response.getEntity();
                String result = WebUtils.convertStreamToString(entity.getContent());
                log.error("Failed to validate the Verifier Response with error message: {}", result);
                throw new OID4VPException(OID4VPEnumError.FAILED_TO_VALIDATE_VP_TOKEN_THROUGH_VERIFIER, "It was impossible to validate the VP Token. An error message was received from the OID4VP Verifier.");
            }
            catch (IOException e){
				log.error("Couldn't retrieve the error message from the failed validation response: {}", e.getMessage());
                throw new OID4VPException(OID4VPEnumError.UNEXPECTED_ERROR, "It was impossible to retrieve the validation response from the Verifier.");
            }
        }
    }

    public String getNonce(String user) throws OID4VPException {
        VerifierCreatedVariable variables = retrieveVerifierVariables(user);
        return variables.getNonce();
    }

    public JSONObject validateSDJWTResponse(String SD_JWT_Device_Response, String nonce) throws OID4VPException{
        Map<String, String> headers = new HashMap<>();
        headers.put("accept", "application/json");
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        String body = "sd_jwt_vc="+SD_JWT_Device_Response+"&nonce="+nonce;

        HttpResponse response;
        try{
            response = WebUtils.httpPostRequest("https://verifier-backend.eudiw.dev/utilities/validations/sdJwtVc", headers, body);
        }
        catch (Exception e){
            log.error("An error occurred when trying to make a request to the Verifier. {}", e.getMessage());
            throw new OID4VPException(OID4VPEnumError.FAILED_CONNECTION_TO_VERIFIER, "It wasn't possible to validate the Verifier Response.");
        }

        if(response.getStatusLine().getStatusCode() == 200){
            log.info("Successfully validated verifier response (Status Code: 200).");

            JSONObject responseVerifier;
            try {
                String result = WebUtils.convertStreamToString(response.getEntity().getContent());
                responseVerifier = new JSONObject(result);
                log.info("Parsed the validation response.");
            }
            catch (IOException e){
                log.error("It was impossible to retrieve the content from the validation request to the OID4VP Verifier.");
                throw new OID4VPException(OID4VPEnumError.UNEXPECTED_ERROR, "It was impossible to retrieve the validation response from the Verifier.");
            }
            catch (JSONException e){
                log.error("It was impossible to parse validation response as a JSON Object.");
                throw new OID4VPException(OID4VPEnumError.RESPONSE_VERIFIER_WITH_INVALID_FORMAT, "The Verifier's validation response is not a valid JSON Array.");
            }

            // Validate 'vct'
            if(!responseVerifier.has("vct") || !responseVerifier.getString("vct").equals("urn:eudi:pid:1")) {
                throw new OID4VPException(OID4VPEnumError.FAILED_TO_VALIDATE_VP_TOKEN_THROUGH_VERIFIER, "It was impossible to validate the VP Token. An error message was received from the OID4VP Verifier.");
            }

            log.info(String.valueOf(responseVerifier));

            // Retrieve 'attributes'
            JSONObject attributes = new JSONObject();
            attributes.put("family_name", responseVerifier.get("family_name"));
            attributes.put("given_name", responseVerifier.get("given_name"));
            attributes.put("birth_date", responseVerifier.get("birthdate"));
            attributes.put("issuing_country", responseVerifier.get("issuing_country"));
            attributes.put("issuing_authority", responseVerifier.get("issuing_authority"));
            return attributes;
        }
        else{
            try {
                HttpEntity entity = response.getEntity();
                String result = WebUtils.convertStreamToString(entity.getContent());
                log.error("Failed to validate the Verifier Response with error message: {}", result);
                throw new OID4VPException(OID4VPEnumError.FAILED_TO_VALIDATE_VP_TOKEN_THROUGH_VERIFIER, "It was impossible to validate the VP Token. An error message was received from the OID4VP Verifier.");
            }
            catch (IOException e){
                log.error("Couldn't retrieve the error message from the failed validation response: {}", e.getMessage());
                throw new OID4VPException(OID4VPEnumError.UNEXPECTED_ERROR, "It was impossible to retrieve the validation response from the Verifier.");
            }
        }
    }
}
