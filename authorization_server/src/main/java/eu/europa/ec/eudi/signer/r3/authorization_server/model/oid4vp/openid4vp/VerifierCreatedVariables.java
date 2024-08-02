package eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.stereotype.Component;

@Component
// @SessionScope
public class VerifierCreatedVariables {
    private volatile ConcurrentMap<String, VerifierCreatedVariable> allVariables;

    public VerifierCreatedVariables() {
        this.allVariables = new ConcurrentHashMap<>();
    }

    public Map<String, VerifierCreatedVariable> getAllVariables() {
        return this.allVariables;
    }

    public boolean containsUser(String user) {
        return allVariables.containsKey(user);
    }

    public synchronized VerifierCreatedVariable getUsersVerifierCreatedVariable(String user, String typeOperation) {
        VerifierCreatedVariable vcv = allVariables.get(user);
        if (vcv != null && vcv.getType().equals(typeOperation)) {
            allVariables.remove(user);
            return vcv;
        } else
            return null;
    }

    public synchronized void addUsersVerifierCreatedVariable(String user, String typeOperation, String nonce,
            String presentation_id) {
        allVariables.put(user, new VerifierCreatedVariable(typeOperation, nonce, presentation_id));
    }

    /*
     * public synchronized void removeUsersVerifierCreatedVariable(String user){
     * allVariables.remove(user);
     * }
     */

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (String key : allVariables.keySet()) {
            sb.append("{ " + key + ": " + allVariables.get(key).getNonce() + " | "
                    + allVariables.get(key).getPresentation_id() + " }\n");
        }
        sb.append("----------------------------------------\n");
        return sb.toString();
    }
}
