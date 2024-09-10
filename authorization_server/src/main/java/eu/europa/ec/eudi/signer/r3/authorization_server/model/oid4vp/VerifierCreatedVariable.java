package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import java.util.Objects;

public class VerifierCreatedVariable {
    private String nonce;
    private String presentation_id;

    public VerifierCreatedVariable(String nonce, String presentation_id) {
        this.nonce = nonce;
        this.presentation_id = presentation_id;
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

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        VerifierCreatedVariable that = (VerifierCreatedVariable) o;
        return Objects.equals(nonce, that.nonce) &&
                Objects.equals(presentation_id, that.presentation_id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(nonce, presentation_id);
    }
}
