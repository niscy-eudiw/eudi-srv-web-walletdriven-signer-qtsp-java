package eu.europa.ec.eudi.signer.r3.authorization_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "oid4vp")
public class OID4VPConfig {
	private VerifierConfig verifier;
	private WalletConfig wallet;

	public VerifierConfig getVerifier() {
		return verifier;
	}

	public void setVerifier(VerifierConfig verifier) {
		this.verifier = verifier;
	}

	public WalletConfig getWallet() {
		return wallet;
	}

	public void setWallet(WalletConfig wallet) {
		this.wallet = wallet;
	}

	public static class WalletConfig{
		private String scheme;

		public String getScheme() {
			return scheme;
		}

		public void setScheme(String scheme) {
			this.scheme = scheme;
		}
	}
}


