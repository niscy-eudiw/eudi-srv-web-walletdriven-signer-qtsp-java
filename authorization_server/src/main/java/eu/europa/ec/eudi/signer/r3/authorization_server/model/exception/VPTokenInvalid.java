package eu.europa.ec.eudi.signer.r3.authorization_server.model.exception;

public class VPTokenInvalid extends Exception {
    public static int Default = -1;

    public SignerError error;

    public VPTokenInvalid(SignerError error, String message) {
        super(message);
        this.error = error;
    }

    public SignerError getError() {
        return this.error;
    }
}
