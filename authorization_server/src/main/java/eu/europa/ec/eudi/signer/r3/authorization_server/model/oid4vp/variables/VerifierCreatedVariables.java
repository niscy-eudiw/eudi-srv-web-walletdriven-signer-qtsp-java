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

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class VerifierCreatedVariables {
    private final ConcurrentMap<String, VerifierCreatedVariable> allVariables;
    private final long EXPIRY_DURATION_MINUTES = 60; // Example expiry time

    public VerifierCreatedVariables() {
        this.allVariables = new ConcurrentHashMap<>();
    }

    public synchronized VerifierCreatedVariable getUsersVerifierCreatedVariable(String sessionId) {
        VerifierCreatedVariable vcv = allVariables.get(sessionId);
        if (vcv != null) {
            removeVerifierCreatedVariable(sessionId);
            return vcv;
        }
        else return null;
    }

    public synchronized void addUsersVerifierCreatedVariable(String sessionId, String nonce, String presentation_id) {
        allVariables.put(sessionId, new VerifierCreatedVariable(nonce, presentation_id, LocalDateTime.now()));
    }

    public synchronized void removeVerifierCreatedVariable(String sessionId){
        allVariables.remove(sessionId);
    }

    @Scheduled(fixedRate = 3600 * 1000) // Run every hour
    public void cleanupExpiredEntries() {
        LocalDateTime now = LocalDateTime.now();
		allVariables.entrySet().removeIf(entry -> entry.getValue().getTimestamp().plusMinutes(EXPIRY_DURATION_MINUTES).isBefore(now));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (String key : allVariables.keySet()) {
            sb.append("{ ").append(key).append(": ").append(allVariables.get(key).getNonce()).append(" | ").append(allVariables.get(key).getTransaction_id()).append(" }\n");
        }
        sb.append("----------------------------------------\n");
        return sb.toString();
    }

    public static class VerifierCreatedVariable {
        private final String nonce;
        private final String transaction_id;
        private final LocalDateTime timestamp;

        public VerifierCreatedVariable(String nonce, String presentation_id, LocalDateTime timestamp) {
            this.nonce = nonce;
            this.transaction_id = presentation_id;
            this.timestamp = timestamp;
        }

        public String getNonce() {
            return nonce;
        }

        public String getTransaction_id() {
            return transaction_id;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof VerifierCreatedVariable that)) return false;
            return Objects.equals(nonce, that.nonce) && Objects.equals(transaction_id, that.transaction_id) && Objects.equals(timestamp, that.timestamp);
        }

        @Override
        public int hashCode() {
            return Objects.hash(nonce, transaction_id, timestamp);
        }
    }
}
