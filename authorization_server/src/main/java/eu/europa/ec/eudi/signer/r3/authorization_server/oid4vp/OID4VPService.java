package eu.europa.ec.eudi.signer.r3.authorization_server.oid4vp;

import org.json.JSONObject;
import org.springframework.stereotype.Service;

// Similar to the OID4VP components from the R2
@Service
public class OID4VPService {

    public JSONObject authorizationRequest(){
        return new JSONObject();
    }

    public String getLinkFromAuthorizationRequestOutput(JSONObject authorizationRequestOutput){
        return "";
    }

    public String getLinkForAuthorizationResponse(){
        return "";
    }

    // get VP Token
    public JSONObject getAuthorizationResponse(){
        return new JSONObject();
    }



    public boolean serviceAuthenticationWithOID4VP() {
        JSONObject authorizationRequestOutput = authorizationRequest();
        String redirectionLink = getLinkFromAuthorizationRequestOutput(authorizationRequestOutput);

        String linkForAuthorizationResponse = getLinkForAuthorizationResponse();
        JSONObject authorizationResponse = getAuthorizationResponse();

        // get VP Token from authorizationResponse;
        // validate VP Token

        return true;
    }

    public boolean credentialAuthorizationWithOID4VP() {
        return true;
    }

}
