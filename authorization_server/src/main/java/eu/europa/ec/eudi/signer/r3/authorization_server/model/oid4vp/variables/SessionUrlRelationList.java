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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SessionUrlRelationList {
    private static final Duration EXPIRY_DURATION = Duration.ofMinutes(60);

    private final ConcurrentMap<String, SessionUrlRelation> listOfVariables = new ConcurrentHashMap<>();

    public SessionUrlRelation getSessionInformation(String sessionId){
        SessionUrlRelation relation = this.listOfVariables.get(sessionId);
        if (relation == null) return null;
        if (relation.isExpired(Instant.now())) {
            this.listOfVariables.remove(sessionId, relation);
            return null;
        }
        return relation;
    }

    public SessionUrlRelation getAndRemoveSessionInformation(String sessionId){
        SessionUrlRelation relation = this.listOfVariables.remove(sessionId);
        return (relation == null || relation.isExpired(Instant.now())) ? null : relation;
    }

    public void removeSessionInformation(String sessionId){
        this.listOfVariables.remove(sessionId);
    }

    public void addSessionReturnToUrl(String sessionId, String url){
        addSessionReturnToUrlAndWalletLink(sessionId, url, null);
    }

    public void addSessionReturnToUrlAndWalletLink(String sessionId, String url, String walletLink){
        this.listOfVariables.put(sessionId, new SessionUrlRelation(url, walletLink, Instant.now().plus(EXPIRY_DURATION)));
    }

    @Scheduled(fixedRate = 5 * 60 * 1000) // Run every 5 minutes
    public void cleanupExpiredEntries() {
        Instant now = Instant.now();
        listOfVariables.values().removeIf(v -> v.isExpired(now));
    }

    public static class SessionUrlRelation {
        private final String urlToReturnTo;
        private final String walletLink;
        private final Instant expiresAt;

        public SessionUrlRelation(String urlToReturnTo, String walletLink, Instant expiresAt) {
            this.urlToReturnTo = urlToReturnTo;
            this.walletLink = walletLink;
            this.expiresAt = expiresAt;
        }

        public String getUrlToReturnTo() {
            return urlToReturnTo;
        }

        public String getWalletLink() {
            return walletLink;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }

        boolean isExpired(Instant now) {
            return now.isAfter(expiresAt);
        }
    }
}
