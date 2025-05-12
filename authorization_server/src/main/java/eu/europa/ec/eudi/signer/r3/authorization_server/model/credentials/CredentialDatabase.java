/*
 Copyright 2025 European Commission

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
