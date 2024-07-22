package eu.europa.ec.eudi.signer.r3.qtsp.model.database.repositories;

import eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities.Credentials;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialsRepository extends JpaRepository<Credentials, String> {
    List<Credentials> findByUserID(String userID);
    Optional<Credentials> findById(String id);
    @Query(value="SELECT c.id FROM credentials c WHERE c.privateKey = ?1 and c.publicKey = ?2 and c.certificate = ?3", nativeQuery=true)
    Optional<String> existsByPrivateKeyAndPublicKeyAndCertificate(String privateKey, String publicKey, String certificate);
}
