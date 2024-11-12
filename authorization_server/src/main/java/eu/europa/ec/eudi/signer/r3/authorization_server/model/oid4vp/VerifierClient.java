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

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.VerifierCreatedVariable;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.VerifierCreatedVariables;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.exception.SignerError;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.VerifierConfig;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
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
    public String initPresentationTransaction(String userId, String currentServiceUrl) throws Exception {
        log.info("Starting Presentation Request and redirection link generation for the user {}", userId);
        String nonce = getNonce();

        // makes the http Presentation Request:
        JSONObject responseFromVerifier;
        try {
            responseFromVerifier = httpRequestToInitPresentation(userId, currentServiceUrl, nonce);
        } catch (Exception e) {
            throw new Exception(SignerError.FailedConnectionToVerifier.getFormattedMessage());
        }
        log.info("Successfully completed the HTTP Post Presentation Request for authentication of the user {}", userId);

        // Validates if the values required are present in the JSON Object Response:
        Set<String> keys = responseFromVerifier.keySet();
        if (!keys.contains("request_uri") || !keys.contains("client_id") || !keys.contains("presentation_id"))
            throw new Exception(SignerError.MissingDataInResponseVerifier.getFormattedMessage());
        String request_uri = responseFromVerifier.getString("request_uri");
        String encoded_request_uri = URLEncoder.encode(request_uri, StandardCharsets.UTF_8);
        String client_id = responseFromVerifier.getString("client_id");
        if(!client_id.equals(this.verifierProperties.getAddress()))
            throw new Exception(SignerError.UnexpectedError.getFormattedMessage());
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

    private JSONObject httpRequestToInitPresentation(String userId, String serviceUrl, String nonce) throws Exception {
        Map<String, String> headers = getHeaders();
        String bodyMessage = getBody(userId, serviceUrl, nonce);

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
            log.error("[Error {}] HTTP Post request to Verifier was not successful." +
                  " Error Message: {} ", statusCode, error);
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
            log.error("The response of the presentation request from the Verifier " +
                  "doesn't contain a correctly formatted JSON string.");
            throw new Exception("The response of the presentation request from the Verifier " +
                  "doesn't contain a correctly formatted JSON string.");
        }
        return responseVerifier;
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        return headers;
    }

    private String getBody(String userId, String serviceUrl, String nonce) {
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
        JSONObject presentationDefinitionJsonObject = new JSONObject(presentationDefinition);

        String redirectUri = serviceUrl+"/oid4vp/callback?session_id="+userId+"&response_code={RESPONSE_CODE}";

        // Set JSON Body
        JSONObject jsonBodyToInitPresentation = new JSONObject();
        jsonBodyToInitPresentation.put("type", "vp_token");
        jsonBodyToInitPresentation.put("nonce", nonce);
        jsonBodyToInitPresentation.put("presentation_definition", presentationDefinitionJsonObject);
        jsonBodyToInitPresentation.put("wallet_response_redirect_uri_template", redirectUri);
        return jsonBodyToInitPresentation.toString();
    }

    private String getLinkToWallet(String request_uri, String client_id) {
        return "eudi-openid4vp://" +
                verifierProperties.getAddress() +
                "?client_id=" +
                client_id +
                "&request_uri=" +
                request_uri;
    }

    /**
     * Function that allows to retrieve the VP Token from the Verifier
     * @param userId an identifier of the user that made the request
     * @param code the code returned by the verifier and required to retrieve the VP Token
     * @return a json formatted string with the vp token
     */
    public String getVPTokenFromVerifier(String userId, String code) throws Exception {
        log.info("Starting to retrieve the VP Token to authenticate the user {}...", userId);

        VerifierCreatedVariable variables = verifierVariables.getUsersVerifierCreatedVariable(userId);
        if (variables == null) {
            log.error("Failed to retrieve the required local variables to complete the authentication.");
            throw new Exception(SignerError.UnexpectedError.getFormattedMessage());
        }
        log.info("Retrieved the required local variables to complete the authentication.");

        log.info("Current Verifier Variables State: {}", verifierVariables);
        log.info("User: {} & Nonce: {} & Presentation_id: {}", userId, variables.getNonce(), variables.getPresentation_id());

        Map<String, String> headers = getHeaders();
        String url = getUrlToRetrieveVPToken(variables.getPresentation_id(), variables.getNonce(), code);
        log.info("Obtained the link to retrieve the VP Token from the verifier.");

        WebUtils.StatusAndMessage response;
        try {
            response = WebUtils.httpGetRequests(url, headers);
        } catch (Exception e) {
            log.error("Failed to retrieve the VP Token. Error: {}", e.getMessage());
            throw new Exception(SignerError.FailedConnectionToVerifier.getFormattedMessage());
        }

        if (response.getStatusCode() == 404) {
            log.error("Failed to connect with Verifier and retrieve the VP Token.");
            throw new Exception(SignerError.FailedConnectionToVerifier.getFormattedMessage());
        }
        log.info("Successfully retrieved the json string with the VP Token.");
        return response.getMessage();
    }

    private String getUrlToRetrieveVPToken(String presentation_id, String nonce, String code) {
        return verifierProperties.getUrl() + "/" + presentation_id + "?nonce=" +
                nonce + "&response_code=" + code;
    }
}
