package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.formLogin;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token.ICommonTokenStructure;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UsernamePasswordAuthenticationTokenExtended extends UsernamePasswordAuthenticationToken implements ICommonTokenStructure {

	private String client_id;
	private String redirect_uri;
	private String scope;

	private String hashDocument;
	private String credentialID;
	private String hashAlgorithmOID;
	private String numSignatures;

	private String authorization_details;

	public UsernamePasswordAuthenticationTokenExtended(Object principal, Object credentials) {
		super(principal, credentials);
	}

	public UsernamePasswordAuthenticationTokenExtended(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
		super(principal, credentials, authorities);
	}

	public String getClient_id() {
		return client_id;
	}

	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}

	public String getRedirect_uri() {
		return redirect_uri;
	}

	public void setRedirect_uri(String redirect_uri) {
		this.redirect_uri = redirect_uri;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public String getHashDocument() {
		return hashDocument;
	}

	public void setHashDocument(String hashDocument) {
		this.hashDocument = hashDocument;
	}

	public String getCredentialID() {
		return credentialID;
	}

	public void setCredentialID(String credentialID) {
		this.credentialID = credentialID;
	}

	public String getHashAlgorithmOID() {
		return hashAlgorithmOID;
	}

	public void setHashAlgorithmOID(String hashAlgorithmOID) {
		this.hashAlgorithmOID = hashAlgorithmOID;
	}

	public String getNumSignatures() {
		return numSignatures;
	}

	public void setNumSignatures(String numSignatures) {
		this.numSignatures = numSignatures;
	}

	public String getAuthorization_details() {
		return authorization_details;
	}

	public void setAuthorization_details(String authorization_details) {
		this.authorization_details = authorization_details;
	}

	@Override
	public String toString() {
		return "UsernamePasswordAuthenticationTokenExtended{" +
			  "client_id='" + client_id + '\'' +
			  ", redirect_uri='" + redirect_uri + '\'' +
			  ", scope='" + scope + '\'' +
			  ", hashDocument='" + hashDocument + '\'' +
			  ", credentialID='" + credentialID + '\'' +
			  ", hashAlgorithmOID='" + hashAlgorithmOID + '\'' +
			  ", numSignatures='" + numSignatures + '\'' +
			  ", authorization_details='" + authorization_details + '\'' +
			  '}';
	}
}
