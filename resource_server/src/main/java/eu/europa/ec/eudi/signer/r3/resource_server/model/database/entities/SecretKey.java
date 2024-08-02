package eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "secret_key")
public class SecretKey {
    @Id
    private String id;

    @Column(nullable = true, length = 2000)
    private byte[] secretKey;

    public SecretKey() {
        this.id = UUID.randomUUID().toString();
    }

    public SecretKey(byte[] sk) {
        this.id = UUID.randomUUID().toString();
        this.secretKey = sk;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(byte[] sk) {
        this.secretKey = sk;
    }
}

