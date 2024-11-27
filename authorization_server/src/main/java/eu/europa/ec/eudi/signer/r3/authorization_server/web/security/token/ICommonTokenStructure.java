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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token;

public interface ICommonTokenStructure {
	void setClient_id(String client_id);
	String getClient_id();

	void setRedirect_uri(String redirect_uri);
	String getRedirect_uri();

	String getScope();
	void setScope(String scope);

	void setHashDocument(String hashDocument);
	String getHashDocument();

	void setCredentialID(String credentialID);
	String getCredentialID();

	void setHashAlgorithmOID(String hashAlgorithmOID);
	String getHashAlgorithmOID();

	void setNumSignatures(String numSignatures);
	String getNumSignatures();

	void setAuthorization_details(String authorization_details);
	String getAuthorization_details();
}
