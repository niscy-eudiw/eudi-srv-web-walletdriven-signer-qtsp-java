package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.TrustedIssuersCertificateConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

@Component
public class TrustedIssuersCertificates {
    private final TrustedIssuersCertificateConfig trustedIssuersCertificates;

    public TrustedIssuersCertificates(@Autowired TrustedIssuersCertificateConfig trustedIssuersCertificates) {
        this.trustedIssuersCertificates = trustedIssuersCertificates;
    }

    public X509Certificate searchForIssuerCertificate(X500Principal issuer) {
        return this.trustedIssuersCertificates.getTrustIssuersCertificates().get(issuer.toString());
    }
}
