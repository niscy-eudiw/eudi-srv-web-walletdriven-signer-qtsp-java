package eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.issuer;

import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaService;
import java.security.cert.X509Certificate;
import java.util.List;

public class EjbcaCertificateIssuer implements ICertificateIssuer {

	private final EjbcaService ejbcaService;

	public EjbcaCertificateIssuer(EjbcaService ejbcaService) {
		this.ejbcaService = ejbcaService;
	}

	@Override
	public List<X509Certificate> issueCertificate(String certificateString, String countryCode) throws Exception {
		return this.ejbcaService.certificateRequest(certificateString, countryCode);
	}

	@Override
	public String getExpectedIssuerSubjectCN(String expectedCountryCode){
		return this.ejbcaService.getCertificateAuthorityNameByCountry(expectedCountryCode);
	}
}
