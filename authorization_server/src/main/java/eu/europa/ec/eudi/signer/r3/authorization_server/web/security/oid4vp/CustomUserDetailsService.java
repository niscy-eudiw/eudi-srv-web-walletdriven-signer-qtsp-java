package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp;

import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    /**
     * Loads the user with a given username if it is present in the database
     * This class expects the username to be composed by "hash";"givenName";"surname"
     * */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String[] n = username.split(";");
        User user = userRepository.findByHash(n[0]).orElseThrow(() -> new UsernameNotFoundException("User not found with hash: ." + n[0]));
        return UserPrincipal.create(user.getId(), user.getHash(), user.getRole(), n[1], n[2], user.getPassword());
    }
}
