package eu.europa.ec.eudi.signer.r3.resource_server.model.keys;

import java.security.PublicKey;

public class KeyPairRegister {
    private byte[] privateKeyBytes;
    private PublicKey publicKeyValue;

    public byte[] getPrivateKeyBytes() {
        return privateKeyBytes;
    }

    public void setPrivateKeyBytes(byte[] privateKeyBytes) {
        this.privateKeyBytes = privateKeyBytes;
    }

    public PublicKey getPublicKeyValue() {
        return publicKeyValue;
    }

    public void setPublicKeyValue(PublicKey publicKeyValue) {
        this.publicKeyValue = publicKeyValue;
    }
}
