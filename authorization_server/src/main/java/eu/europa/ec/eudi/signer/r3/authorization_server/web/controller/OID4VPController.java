package eu.europa.ec.eudi.signer.r3.authorization_server.web.controller;

import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.OpenId4VPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.openid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.User;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.user.UserRepository;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.provider.AuthorizationRequestProviderAfterAuthentication;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.authentication.CustomAuthenticationSuccessHandler;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp.OpenId4VPAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

@RestController
@RequestMapping(value = "/oid4vp")
public class OID4VPController {
    private static final Logger log = LoggerFactory.getLogger(OID4VPController.class);
    private final VerifierClient verifierClient;
    private final UserRepository userRepository;
    private final OpenId4VPService service;
    private final AuthorizationRequestProviderAfterAuthentication authorizationRequestProviderAfterAuthentication;
    private final Consumer<OAuth2User> oauth2UserHandler = (user) -> {};

    public OID4VPController(
          @Autowired VerifierClient verifierClient,
          @Autowired UserRepository userRepository,
          @Autowired OpenId4VPService openId4VPService,
          @Autowired AuthorizationRequestProviderAfterAuthentication authorizationRequestProviderAfterAuthentication){
        this.verifierClient = verifierClient;
        this.userRepository = userRepository;
        this.service = openId4VPService;
        this.authorizationRequestProviderAfterAuthentication = authorizationRequestProviderAfterAuthentication;
    }

    // Request the VP Token and Validates
    // operation == VerifierClient.Authentication || operation == VerifierClient.Authorization
    @GetMapping("/callback")
    public void callback_endpoint(HttpServletRequest request, HttpServletResponse response){
        String code = request.getParameter("response_code");
        System.out.println("response_code: "+code);

        try {
            String user = "some_user";

            // get the authorization response from the oid4vp verifier
            String messageFromVerifier = this.verifierClient.getVPTokenFromVerifier(user, VerifierClient.Authentication, code);
            System.out.println("messageFromVerifier: "+messageFromVerifier);
            if (messageFromVerifier == null) throw new Exception("Error when trying to obtain the vp_token from Verifier.");

            OpenId4VPAuthenticationToken userAuthentication = this.service.loadUserFromVerifierResponseAndGetJWTToken(messageFromVerifier);
            System.out.println("Username: "+userAuthentication.getUsername());

            User userObject = userRepository.findByHash(userAuthentication.getHash()).orElseThrow(() -> new UsernameNotFoundException("User not found with hash: ." + userAuthentication.getHash()));
            UserPrincipal userPrincipal = UserPrincipal.create(userObject, userAuthentication.getGivenName(), userAuthentication.getSurname());

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("client_id", "sca-client");
            attributes.put("id", userPrincipal.getId());
            attributes.put("givenName", userPrincipal.getGivenName());
            attributes.put("surname", userPrincipal.getSurname());
            attributes.put("fullName", userPrincipal.getName());
            attributes.put("hash", userPrincipal.getUsername());

            DefaultOAuth2User defaultOAuth2User = new DefaultOAuth2User(
                  userPrincipal.getAuthorities(),
                  attributes,
                  "client_id"
                  );

            // OpenId4VPAuthenticationToken userAuthentication_2 = new OpenId4VPAuthenticationToken(userPrincipal, userPrincipal.getAuthorities());
            OAuth2AuthenticationToken userAuthentication2 = new OAuth2AuthenticationToken(defaultOAuth2User, userPrincipal.getAuthorities(), "sca-client");
            this.oauth2UserHandler.accept(userAuthentication2.getPrincipal());

            // SecurityContextHolder.getContext().setAuthentication(userAuthentication2);

            Set<String> scopes = new HashSet<>();
            scopes.add("service");

            Authentication authenticationToken = new OAuth2AuthorizationCodeRequestAuthenticationToken (
                  "/oauth2/authorize", "sca-client",
                  userAuthentication2, "http://localhost:8080/login/oauth2/code/sca-client",
                  "state", scopes, new HashMap<>()
            );
            // AuthorizationRequestProviderAfterAuthentication auth = new AuthorizationRequestProviderAfterAuthentication(this.registeredClientRepository, this.authorizationService);
            Authentication authentication = this.authorizationRequestProviderAfterAuthentication.authenticate(authenticationToken);

            if(!authentication.isAuthenticated()){
                System.out.println("not authenticated");
            }

            CustomAuthenticationSuccessHandler authenticationSuccessHandler = new CustomAuthenticationSuccessHandler();
            authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
        }
        catch (Exception e){
            e.printStackTrace();
            response.setStatus(404);
        }
    }
}