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

package eu.europa.ec.eudi.signer.r3.authorization_server;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.ManageOAuth2Authorization;
import org.apache.logging.log4j.LogManager;

import org.apache.logging.log4j.Logger;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class RemoveExpiredAuthorization implements SmartLifecycle {
    private static final Logger logger = LogManager.getLogger(RemoveExpiredAuthorization.class);

    private Thread removePDFsThread;
    private boolean running = false;
    private final int timeSleepThread;
    private final ManageOAuth2Authorization manageOAuth2Authorization;

    public RemoveExpiredAuthorization(ManageOAuth2Authorization manageOAuth2Authorization) {
        this.timeSleepThread = 86400;
        this.manageOAuth2Authorization = manageOAuth2Authorization;
    }

    @Override
    public void start() {
        removePDFsThread = new Thread(() -> {
            while (running) {
                try {
                    this.manageOAuth2Authorization.removeExpiredAccessTokens(Instant.now());
                    Thread.sleep(timeSleepThread * 1000L);
                } catch (InterruptedException e) {
                    logger.warn("Interrupted Thread", e);
                    Thread.currentThread().interrupt();
                }
            }
        });
        running = true;
        removePDFsThread.start();
    }

    @Override
    public void stop() {
        running = false;
        if (removePDFsThread != null) {
            removePDFsThread.interrupt();
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return 0;
    }

    @Override
    public void stop(Runnable callback) {
        stop();
        callback.run();
    }
}
