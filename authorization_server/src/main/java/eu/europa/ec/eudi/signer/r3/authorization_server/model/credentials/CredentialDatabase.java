package eu.europa.ec.eudi.signer.r3.authorization_server.model.credentials;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class CredentialDatabase {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	public List<String> findByUserIDAndSignatureQualifier(String userID, String signatureQualifier){
		String sqlQuery = "SELECT c.id FROM credentials c WHERE c.userID = ? and c.signatureQualifier = ?";
		return jdbcTemplate.queryForList(sqlQuery, String.class, userID, signatureQualifier);
	}
}
