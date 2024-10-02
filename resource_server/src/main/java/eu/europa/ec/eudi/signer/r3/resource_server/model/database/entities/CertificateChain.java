package eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities;

import jakarta.persistence.*;

@Entity
@Table(name="certificate_chain")
public class CertificateChain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 2000)
    private String certificate;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "credentials_id", nullable = false)
    private Credentials credential;

    public CertificateChain() {
    }

    public CertificateChain(long id, String certificate) {
        this.id = id;
        this.certificate = certificate;
    }

    public String getCertificate() {
        return this.certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public Credentials getCredential() {
        return this.credential;
    }

    public void setCredential(Credentials credential) {
        this.credential = credential;
    }
}
