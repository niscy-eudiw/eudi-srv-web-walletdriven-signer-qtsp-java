package eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories;

import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.Credentials;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialsRepository extends JpaRepository<Credentials, String> {

    List<Credentials> findByUserID(String userID);

    Optional<Credentials> findById(String id);

    @Query(value="SELECT c FROM credentials c WHERE c.userID = ?1 and c.id = ?2", nativeQuery=true)
    Optional<Credentials> findByUserIDAndId(String userID, String id);

    @Query(value="SELECT c.id FROM credentials c WHERE c.privateKey = ?1 and c.publicKey = ?2 and c.certificate = ?3", nativeQuery=true)
    Optional<String> existsByPrivateKeyAndPublicKeyAndCertificate(String privateKey, String publicKey, String certificate);
}
