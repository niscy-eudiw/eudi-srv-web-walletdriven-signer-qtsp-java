/*
 Copyright 2025 European Commission

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

package eu.europa.ec.eudi.signer.r3.authorization_server.model.credentials;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class CredentialsService {
    private final CredentialDatabase credentialsRepository;

    public CredentialsService(@Autowired CredentialDatabase credentialDatabase){
        this.credentialsRepository = credentialDatabase;
    }

    /**
     * Function that returns the list of the credentials id available to the user
     * @param userID the user that made the request and that owns the credentials (userHash)
     * @return the list of the credentials id
     */
    public String getCredentialIDFromSignatureQualifier(String userID, String signatureQualifier){
        List<String> credentials = this.credentialsRepository.findByUserIDAndSignatureQualifier(userID, signatureQualifier);
        return credentials.get(0);
    }
}
