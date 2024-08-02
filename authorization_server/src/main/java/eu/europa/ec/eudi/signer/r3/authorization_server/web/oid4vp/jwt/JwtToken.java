package eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp.jwt;


public class JwtToken {
    private String rawToken;
    private String subject;
    private String type;
    private String error;
    private boolean valid;
    private boolean expired;

    public JwtToken(String subject, String type) {
        this.subject = subject;
        this.type = type;
        this.valid = true;
        this.expired = false;
    }

    private JwtToken() {
    }

    /**
     * Create an object that represent a token that's already considered invalid.
     *
     * @param error error message explaining why the token is in valid
     * @return a new but invalid token
     */
    public static JwtToken invalidToken(String error) {
        JwtToken token = new JwtToken();
        token.valid = false;
        token.error = error;
        return token;
    }

    /**
     * Create an object that represent a token that's already expired.
     *
     * @return a new but invalid token
     */
    public static JwtToken expiredToken() {
        JwtToken token = new JwtToken();
        token.valid = false;
        token.expired = true;
        token.error = "JWT token is expired";
        return token;
    }

    public String getRawToken() {
        return rawToken;
    }

    public void setRawToken(String rawToken) {
        this.rawToken = rawToken;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getError() {
        return error;
    }

    public boolean isValid() {
        return valid;
    }

    public boolean isExpired() {
        return expired;
    }
}
