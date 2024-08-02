package eu.europa.ec.eudi.signer.r3.authorization_server.model.exception;


public class VerifiablePresentationVerificationException extends Exception {

    public static int Default = -1;

    public static int Signature = 8;

    public static int Integrity = 9;

    private final int type;

    private final SignerError error;

    public VerifiablePresentationVerificationException(SignerError error, String message, int type) {
        super("Verification of the Verifiable Presentation Failed: " + message);

        if (type == Signature) {
            this.type = Signature;
        } else if (type == Integrity) {
            this.type = Integrity;
        } else
            this.type = Default;

        this.error = error;
    }

    public int getType() {
        return this.type;
    }

    public SignerError getError() {
        return this.error;
    }
}