package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables;

public class SessionUrlRelation {
    private String cookieSessionId;
    private String urlToReturnTo;

    public SessionUrlRelation(String urlToReturnTo, String cookieSessionId) {
        this.urlToReturnTo = urlToReturnTo;
        this.cookieSessionId = cookieSessionId;
    }

    public String getUrlToReturnTo() {
        return urlToReturnTo;
    }

    public void setUrlToReturnTo(String urlToReturnTo) {
        this.urlToReturnTo = urlToReturnTo;
    }

    public String getCookieSessionId() {
        return cookieSessionId;
    }

    public void setCookieSessionId(String cookieSessionId) {
        this.cookieSessionId = cookieSessionId;
    }
}
