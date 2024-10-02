package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

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

    public static String PresentationDefinitionId = "32f54163-7166-48f1-93d8-ff217bdb0653";
    public static String PresentationDefinitionInputDescriptorsId = "eu.europa.ec.eudi.pid.1";

    private static final Logger log = LoggerFactory.getLogger(VerifierClient.class);

    private final VerifierConfig verifierProperties;
    private final VerifierCreatedVariables verifierVariables;

    public VerifierClient(VerifierConfig verifierProperties) {
        this.verifierProperties = verifierProperties;
        this.verifierVariables = new VerifierCreatedVariables();
    }

    /**
     * Function that allows to make a Presentation Request, following the OpenID for
     * Verifiable Presentations - draft 20, to the verifier
     * This function already writes the logs for the ApiException. The message in
     * that exceptions can also be used to display info to the user.
     *
     * @param user an identifier of the user that made the request (ex: a cookie or an id)
     * @return the deep link that redirects the user to the EUDI Wallet
     * @throws Exception
     */
    public AuthorizationRequestVariables initPresentationTransaction(String user, String service_url) throws Exception {
        System.out.println("init user: "+user);
        Map<String, String> headers = getHeaders();
        String nonce = generateNonce();
        String body = getBody(service_url, nonce, user);

        JSONObject responseFromVerifierAfterInitPresentation;
        try {
            responseFromVerifierAfterInitPresentation = httpRequestToInitPresentation(body, headers);
        } catch (Exception e) {
            throw new Exception(SignerError.FailedConnectionToVerifier.getFormattedMessage());
        }

        Set<String> keys = responseFromVerifierAfterInitPresentation.keySet();
        if (!keys.contains("request_uri") || !keys.contains("client_id") || !keys.contains("presentation_id"))
            throw new Exception(SignerError.MissingDataInResponseVerifier.getFormattedMessage());

        String request_uri = responseFromVerifierAfterInitPresentation.getString("request_uri");
        String client_id = responseFromVerifierAfterInitPresentation.getString("client_id");
        if(!client_id.equals(this.verifierProperties.getAddress())) throw new Exception(SignerError.UnexpectedError.getFormattedMessage());

        String presentation_id = responseFromVerifierAfterInitPresentation.getString("presentation_id");
        String encoded_request_uri = URLEncoder.encode(request_uri, StandardCharsets.UTF_8);

        String deepLink = redirectUriDeepLink(encoded_request_uri, client_id);
        // String encoded_return_to = URLEncoder.encode(return_to, StandardCharsets.UTF_8);
        this.verifierVariables.addUsersVerifierCreatedVariable(user, nonce, presentation_id);
        return new AuthorizationRequestVariables(deepLink, nonce, presentation_id);
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        return headers;
    }

    private String generateNonce() throws Exception {
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        return Base64.getUrlEncoder().encodeToString(result);
    }

    private String getBody(String service_url, String nonce, String userCookieSession) throws Exception{
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

        String redirect_uri = service_url+"/oid4vp/callback?&session_id="+userCookieSession+"&response_code={RESPONSE_CODE}";
        System.out.println(redirect_uri);

        // Set JSON Body
        JSONObject jsonBodyToInitPresentation = new JSONObject();
        jsonBodyToInitPresentation.put("type", "vp_token");
        jsonBodyToInitPresentation.put("nonce", nonce);
        jsonBodyToInitPresentation.put("presentation_definition", presentationDefinitionJsonObject);
        jsonBodyToInitPresentation.put("wallet_response_redirect_uri_template", redirect_uri);
        return jsonBodyToInitPresentation.toString();
    }

    private JSONObject httpRequestToInitPresentation(String jsonObjectString, Map<String, String> headers) throws Exception {
        HttpResponse response;
        try {
            response = WebUtils.httpPostRequest(verifierProperties.getUrl(), headers, jsonObjectString);
        } catch (Exception e) {
            throw new Exception("An error occurred when trying to connect to the Verifier");
        }

        if (response.getStatusLine().getStatusCode() != 200) {
            String error = WebUtils.convertStreamToString(response.getEntity().getContent());
            int statusCode = response.getStatusLine().getStatusCode();
            log.error("HTTP Post Request not successful. Error : " + statusCode);
            throw new Exception("HTTP Post Request not successful. Error : " + response.getStatusLine().getStatusCode());
        }

        HttpEntity entity = response.getEntity();
        if (entity == null) {
            throw new Exception("Response to the presentation request is empty.");
        }
        String result = WebUtils.convertStreamToString(entity.getContent());

        JSONObject responseVerifier;
        try{
            responseVerifier =  new JSONObject(result);
        }
        catch (JSONException e){
            throw new Exception("The response from the Verifier doesn't contain a correctly formatted JSON string.");
        }
        return responseVerifier;
    }

    private String redirectUriDeepLink(String request_uri, String client_id) {
        return "eudi-openid4vp://" +
                verifierProperties.getAddress() +
                "?client_id=" +
                client_id +
                "&request_uri=" +
                request_uri;
    }

    public VerifierCreatedVariable getVerifierVariables(String user) throws Exception{
        System.out.println("get user: "+user);
        VerifierCreatedVariable variables = verifierVariables.getUsersVerifierCreatedVariable(user);
        if (variables == null) throw new Exception(SignerError.UnexpectedError.getFormattedMessage());
        return variables;
    }

    /**
     * get authorization response from the oid4vp verifier
     */
    public String getVPTokenFromVerifier(String user, String code, VerifierCreatedVariable variables) throws Exception {
        System.out.println("get user: "+user);

        String nonce = variables.getNonce();
        String presentation_id = variables.getPresentation_id();
        log.info("Current Verifier Variables State: {}", verifierVariables);
        log.info("User {}: Nonce: {} & Presentation_id: {}", user, nonce, presentation_id);

        Map<String, String> headers = getHeaders();
        String url = uriToRequestWalletPID(presentation_id, nonce, code);
        System.out.println(url);

        String message = null;
        WebUtils.StatusAndMessage response;
        try {
            response = WebUtils.httpGetRequests(url, headers);
        } catch (Exception e) {
            throw new Exception(SignerError.FailedConnectionToVerifier.getFormattedMessage());
        }

        if (response.getStatusCode() == 404)
            throw new Exception("Failed connection to Verifier: impossible to get vp_token");
        else if (response.getStatusCode() == 200) {
            message = response.getMessage();
        }
        return message;
    }

    private String uriToRequestWalletPID(String presentation_id, String nonce, String code) {
        return verifierProperties.getUrl() +
                "/" + presentation_id +
                "?nonce=" +
                nonce +
                "&response_code="+
                code;
    }
}
