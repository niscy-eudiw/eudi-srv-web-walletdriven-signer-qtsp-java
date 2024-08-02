package eu.europa.ec.eudi.signer.r3.authorization_server.model.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findByHash(String hash);

    @Query("SELECT u.issuingCountry FROM User u WHERE u.hash = ?1")
    Optional<String> findIssuingCountryByHash(String hash);
}