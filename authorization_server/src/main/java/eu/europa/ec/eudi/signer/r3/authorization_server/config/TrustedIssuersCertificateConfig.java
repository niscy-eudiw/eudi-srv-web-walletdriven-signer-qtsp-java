package eu.europa.ec.eudi.signer.r3.authorization_server.config;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "trusted-issuers")
public class TrustedIssuersCertificateConfig {

    private final String folder;
    private final Map<String, X509Certificate> trustIssuersCertificates;

    public TrustedIssuersCertificateConfig(String folder) throws Exception {
        this.folder = folder;
        this.trustIssuersCertificates = new HashMap<>();

        try (Stream<Path> paths = Files.walk(Paths.get(folder))) {
            paths
                  .filter(path -> Files.isRegularFile(path) && path.toString().endsWith(".pem"))
                  .forEach(path -> {
                      System.out.println("Loading the certificate in the file: " + path);

                      // Process each file here
                      try {
                          CertificateFactory factory = CertificateFactory.getInstance("x.509");
                          FileInputStream is = new FileInputStream(path.toFile().getAbsolutePath());
                          X509Certificate CACert = (X509Certificate) factory.generateCertificate(is);
                          is.close();
                          this.trustIssuersCertificates.put(CACert.getSubjectX500Principal().toString(), CACert);
                      } catch (Exception e1) {
                          throw new RuntimeException(e1);
                      }
                  });
        }
    }

    public String getFolder() {
        return this.folder;
    }

    public Map<String, X509Certificate> getTrustIssuersCertificates() {
        return this.trustIssuersCertificates;
    }

}
