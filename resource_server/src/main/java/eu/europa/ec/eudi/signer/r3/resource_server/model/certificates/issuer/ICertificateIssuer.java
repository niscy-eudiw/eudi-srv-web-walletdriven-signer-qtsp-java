package eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.issuer;

import java.security.cert.X509Certificate;
import java.util.List;

public interface ICertificateIssuer {
	List<X509Certificate> issueCertificate(String certificateSigningRequest, String countryCode) throws Exception;
	String getExpectedIssuerSubjectCN(String expectedCountryCode);
}
