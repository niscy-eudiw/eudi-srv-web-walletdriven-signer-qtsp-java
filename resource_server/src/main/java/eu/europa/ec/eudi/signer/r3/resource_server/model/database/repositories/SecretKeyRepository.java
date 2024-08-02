package eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories;

import java.util.List;

import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.SecretKey;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SecretKeyRepository extends JpaRepository<SecretKey, String> {
    @NotNull
    List<SecretKey> findAll();
}
