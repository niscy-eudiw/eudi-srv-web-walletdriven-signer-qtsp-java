package eu.europa.ec.eudi.signer.r3.authorization_server.web;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Set;

public class ManageOAuth2Authorization {

    private final JdbcOperations jdbcOperations;

    public ManageOAuth2Authorization(JdbcOperations jdbcOperations) {
        this.jdbcOperations = jdbcOperations;
    }

    public void removePreviousOAuth2AuthorizationOfUser(String principal_name, Set<String> authorized_scopes){
        // authorized_scopes
        String authorizedScopes;
        if (!CollectionUtils.isEmpty(authorized_scopes)){
            authorizedScopes = StringUtils.collectionToDelimitedString(authorized_scopes, ",");
            this.jdbcOperations.update("DELETE FROM oauth2_authorization WHERE principal_name = ? and authorized_scopes = ?", principal_name, authorizedScopes);
        }
    }

    public void removeExpiredAccessTokens(Instant now){
        System.out.println(now);
        this.jdbcOperations.update("DELETE FROM oauth2_authorization WHERE access_token_expires_at < ?", now);
    }
}
