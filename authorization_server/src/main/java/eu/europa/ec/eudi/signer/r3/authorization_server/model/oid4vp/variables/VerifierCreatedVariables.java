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

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class VerifierCreatedVariables {
    private static final Duration EXPIRY_DURATION = Duration.ofMinutes(60);
    private final ConcurrentMap<String, VerifierCreatedVariable> allVariables = new ConcurrentHashMap<>();

    public VerifierCreatedVariable getAndRemoveUsersVerifierCreatedVariable(String sessionId) {
        VerifierCreatedVariable vcv = allVariables.remove(sessionId);
        return (vcv == null || vcv.isExpired(Instant.now())) ? null : vcv;
    }

    public VerifierCreatedVariable getUsersVerifierCreatedVariable(String sessionId) {
        VerifierCreatedVariable vcv = allVariables.get(sessionId);
        if (vcv == null) return null;
        if (vcv.isExpired(Instant.now())) {
            allVariables.remove(sessionId, vcv);
            return null;
        }
        return vcv;
    }

    public void addUsersVerifierCreatedVariable(String sessionId, String nonce, String presentation_id) {
        allVariables.put(sessionId, new VerifierCreatedVariable(nonce, presentation_id, Instant.now().plus(EXPIRY_DURATION)));
    }

    public void removeVerifierCreatedVariable(String sessionId){
        allVariables.remove(sessionId);
    }

    @Scheduled(fixedRate = 5 * 60 * 1000) // Run every 5 minutes
    public void cleanupExpiredEntries() {
        Instant now = Instant.now();
        allVariables.values().removeIf(v -> v.isExpired(now));
    }

    @Override
    public String toString() {
        return "VerifierCreatedVariables{entries=" + allVariables.size() + "}";
    }

    public static class VerifierCreatedVariable {
        private final String nonce;
        private final String transaction_id;
        private final Instant expiresAt;

        public VerifierCreatedVariable(String nonce, String presentation_id, Instant expiresAt) {
            this.nonce = nonce;
            this.transaction_id = presentation_id;
            this.expiresAt = expiresAt;
        }

        public String getNonce() {
            return nonce;
        }

        public String getTransaction_id() {
            return transaction_id;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }

        boolean isExpired(Instant now) {
            return now.isAfter(expiresAt);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof VerifierCreatedVariable that)) return false;
            return Objects.equals(nonce, that.nonce) && Objects.equals(transaction_id, that.transaction_id) && Objects.equals(expiresAt, that.expiresAt);
        }

        @Override
        public int hashCode() {
            return Objects.hash(nonce, transaction_id, expiresAt);
        }
    }
}
