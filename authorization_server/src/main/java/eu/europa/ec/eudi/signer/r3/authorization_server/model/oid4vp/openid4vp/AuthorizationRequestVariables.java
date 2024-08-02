package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp;

public class AuthorizationRequestVariables {
    private String redirectLink;
    private String nonce;
    private String presentation_id;

    public String getRedirectLink() {
        return redirectLink;
    }

    public void setRedirectLink(String redirectLink) {
        this.redirectLink = redirectLink;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getPresentation_id() {
        return presentation_id;
    }

    public void setPresentation_id(String presentation_id) {
        this.presentation_id = presentation_id;
    }
}