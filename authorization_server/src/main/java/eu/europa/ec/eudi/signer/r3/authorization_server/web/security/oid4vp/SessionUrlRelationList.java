package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Component;

@Component
public class SessionUrlRelationList {

    private final ConcurrentMap<String, SessionUrlRelation> listOfVariables;

    public SessionUrlRelationList() {
        this.listOfVariables = new ConcurrentHashMap<>();
    }

    public synchronized SessionUrlRelation getSessionInformation(String sessionId){
        return this.listOfVariables.get(sessionId);
    }

    public synchronized void addSessionUrlRelation(String user, String url){
        this.listOfVariables.put(user, new SessionUrlRelation(url, user));
    }


}
