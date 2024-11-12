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

package eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories;

import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.Credentials;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialsRepository extends JpaRepository<Credentials, String> {

    List<Credentials> findByUserID(String userID);

    Optional<Credentials> findById(String id);

    @Query(value="SELECT c.id FROM credentials c WHERE c.userID = ?1 and c.id = ?2", nativeQuery=true)
    Optional<String> findByUserIDAndId(String userID, String id);

    @Query(value="SELECT c.id FROM credentials c WHERE c.privateKey = ?1 and c.publicKey = ?2 and c.certificate = ?3", nativeQuery=true)
    Optional<String> existsByPrivateKeyAndPublicKeyAndCertificate(String privateKey, String publicKey, String certificate);
}
