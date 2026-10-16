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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SessionUrlRelationList {

    private final ConcurrentMap<String, SessionUrlRelation> listOfVariables;
    private final long EXPIRY_DURATION_MINUTES = 60;

    public SessionUrlRelationList() {
        this.listOfVariables = new ConcurrentHashMap<>();
    }

    public synchronized SessionUrlRelation getSessionInformation(String sessionId){
        return this.listOfVariables.get(sessionId);
    }

    public synchronized void removeSessionInformation(String sessionId){
        this.listOfVariables.remove(sessionId);
    }

    public synchronized void addSessionReturnToUrl(String sessionId, String url){
        this.listOfVariables.put(sessionId, new SessionUrlRelation(url, null, LocalDateTime.now()));
    }

    public synchronized void addSessionReturnToUrlAndWalletLink(String sessionId, String url, String walletLink){
        this.listOfVariables.put(sessionId, new SessionUrlRelation(url, walletLink, LocalDateTime.now()));
    }

    @Scheduled(fixedRate = 3600 * 1000)
    public void cleanupExpiredEntries() {
        LocalDateTime now = LocalDateTime.now();
        listOfVariables.entrySet().removeIf(entry -> entry.getValue().getTimestamp().plusMinutes(EXPIRY_DURATION_MINUTES).isBefore(now));
    }

    public static class SessionUrlRelation {
        private final String urlToReturnTo;
        private final String walletLink;
        private final LocalDateTime timestamp;

        public SessionUrlRelation(String urlToReturnTo, String walletLink, LocalDateTime timestamp) {
            this.urlToReturnTo = urlToReturnTo;
            this.walletLink = walletLink;
            this.timestamp = timestamp;
        }

        public String getUrlToReturnTo() {
            return urlToReturnTo;
        }

        public String getWalletLink() {
            return walletLink;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }
    }
}
