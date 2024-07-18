package eu.europa.ec.eudi.signer.r3.qtsp.model.keys.hsm;

import java.util.LinkedList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pkcs11.jacknji11.CE;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.LongRef;

public class HsmInformation {

    private final static Logger log = LoggerFactory.getLogger(HsmInformation.class);
    private final long slot;
    private final byte[] pin;
    private final LinkedList<LongRef> idleSessions = new LinkedList<>();
    private final LinkedList<LongRef> activeSessions = new LinkedList<>();

    public HsmInformation(long slot, byte[] pin) {
        this.slot = slot;
        this.pin = pin;
    }

    public synchronized void releaseSession(LongRef sessionRef) {
        if (activeSessions.contains(sessionRef)) {
            activeSessions.remove(sessionRef);
        } else {
            log.warn("Session not active: " + sessionRef);
        }
        idleSessions.push(sessionRef);
    }

    public synchronized LongRef getSession() throws Exception {
        LongRef sessionRef;
        if (idleSessions.isEmpty()) {
            try {
                long session = CE.OpenSession(this.slot);
                CE.LoginUser(session, pin);
                sessionRef = new LongRef(session);
                if (log.isDebugEnabled()) {
                    log.debug("iddleSessions is empty, adding new session: " + sessionRef.value());
                }
            } catch (CKRException rv) {
                throw new Exception(rv);
            }
        } else {
            sessionRef = idleSessions.pop();
            if (log.isDebugEnabled()) {
                log.debug("Removing session from idle: " + sessionRef.value());
            }
        }
        activeSessions.push(sessionRef);
        return sessionRef;
    }

    // Closing the last session causes the user to be logged out. A new iddle
    // session will be created in this case to prevent logout.
    public synchronized void CloseSession(LongRef sessionRef) throws Exception {
        if (idleSessions.isEmpty() && activeSessions.size() <= 1) {
            releaseSession(getSession());
        }

        try {
            CE.CloseSession(sessionRef.value());
        } catch (CKRException rv) {
            throw new Exception(rv);
        }

        if (activeSessions.contains(sessionRef)) {
            activeSessions.remove(sessionRef);
        } else
            idleSessions.remove(sessionRef);
        if (log.isDebugEnabled()) {
            log.debug("Closed Session: " + sessionRef.value());
        }
    }

}
