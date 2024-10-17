package eu.europa.ec.eudi.signer.r3.authorization_server.model.exception;

public class VPTokenInvalidException extends Exception {
    public static int Default = -1;

    public final SignerError error;

    public VPTokenInvalidException(SignerError error, String message) {
        super(message);
        this.error = error;
    }

    public SignerError getError() {
        return this.error;
    }
}
