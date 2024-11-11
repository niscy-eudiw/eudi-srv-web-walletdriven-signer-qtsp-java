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

package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.stereotype.Component;

@Component
public class VerifierCreatedVariables {
    private final ConcurrentMap<String, VerifierCreatedVariable> allVariables;

    public VerifierCreatedVariables() {
        this.allVariables = new ConcurrentHashMap<>();
    }

    public synchronized VerifierCreatedVariable getUsersVerifierCreatedVariable(String user) {
        VerifierCreatedVariable vcv = allVariables.get(user);
        if (vcv != null) {
            allVariables.remove(user);
            return vcv;
        } else
            return null;
    }

    public synchronized void addUsersVerifierCreatedVariable(String user, String nonce, String presentation_id) {
        allVariables.put(user, new VerifierCreatedVariable(nonce, presentation_id));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (String key : allVariables.keySet()) {
            sb.append("{ ").append(key).append(": ").append(allVariables.get(key).getNonce()).append(" | ").append(allVariables.get(key).getPresentation_id()).append(" }\n");
        }
        sb.append("----------------------------------------\n");
        return sb.toString();
    }
}
