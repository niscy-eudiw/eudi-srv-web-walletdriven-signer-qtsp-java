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
