/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token.ICommonTokenStructure;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class OID4VPAuthenticationToken extends AbstractAuthenticationToken implements ICommonTokenStructure {
    private final String hash;
    private final String username;
    private Object principal;

    private String client_id;
    private String redirect_uri;
    private String scope;

    private String hashDocument;
    private String credentialID;
    private String hashAlgorithmOID;
    private String numSignatures;

    private String authorization_details;

    public OID4VPAuthenticationToken(String hash, String username){
        super(null);
        this.hash = hash;
        this.username = username;
        this.principal = hash;
        super.setAuthenticated(false);
    }

    public static OID4VPAuthenticationToken unauthenticated(String hash, String username){
        return new OID4VPAuthenticationToken(hash, username);
    }

    public static OID4VPAuthenticationToken unauthenticated(String hash, String givenName, String surname){
        String username = hash + ";" + givenName + ";" + surname;
        return new OID4VPAuthenticationToken(hash, username);
    }

    public OID4VPAuthenticationToken(Object userPrincipal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        UserPrincipal user = (UserPrincipal) userPrincipal;
        this.hash = user.getUsername();
        this.username = user.getUsername() + ";" + user.getGivenName() + ";" + user.getSurname();
        this.principal = user;
        super.setAuthenticated(true);
    }

    public static OID4VPAuthenticationToken authenticated(Object userPrincipal, Collection<? extends GrantedAuthority> authorities){
        return new OID4VPAuthenticationToken(userPrincipal, authorities);
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public String getName(){
        if(principal.getClass().equals(UserPrincipal.class)){
            UserPrincipal user = (UserPrincipal) principal;
            return user.getName();
        }
        else return this.principal.toString();
    }

    public void setPrincipal(Object user){
        this.principal = user;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities){}

    @Override
    public Object getCredentials() {
        return null;
    }

    public String getHash() {
        return hash;
    }

    public String getUsername() {
        return username;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public void setRedirect_uri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }

    public void setHashDocument(String hashDocument) {
        this.hashDocument = hashDocument;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public void setNumSignatures(String numSignatures) {
        this.numSignatures = numSignatures;
    }

    public void setAuthorization_details(String authorization_details) {
        this.authorization_details = authorization_details;
    }

    public String getClient_id() {
        return client_id;
    }

    public String getRedirect_uri() {
        return redirect_uri;
    }

    public String getHashDocument() {
        return hashDocument;
    }

    public String getCredentialID() {
        return credentialID;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public String getNumSignatures() {
        return numSignatures;
    }

    public String getAuthorization_details() {
        return authorization_details;
    }

    @Override
    public String toString() {
        return "AuthenticationManagerToken{" +
              "hash='" + hash + '\'' +
              ", username='" + username + '\'' +
              ", principal=" + principal +
              ", client_id='" + client_id + '\'' +
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
