package eu.europa.ec.eudi.signer.r3.resource_server.web.controllers;

import eu.europa.ec.eudi.signer.r3.common_tools.utils.UserPrincipal;
import eu.europa.ec.eudi.signer.r3.resource_server.config.CredentialsConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;


import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListResponse;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoResponse;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(value = "/csc/v2/credentials")
public class CredentialsController {

    private final CredentialsService credentialsService;
    private final CredentialsConfig credentialsConfig;
    private final User user_for_tests;


    public CredentialsController(@Autowired CredentialsService credentialsService, @Autowired CredentialsConfig credentialsConfig) throws Exception{
        this.credentialsService = credentialsService;
        this.credentialsConfig = credentialsConfig;
        this.user_for_tests = new User();
    }

    @PostMapping(value = "/list", consumes = "application/json", produces = "application/json")
    public CredentialsListResponse list(@RequestBody CredentialsListRequest listRequestDTO) {
        System.out.println(listRequestDTO.toString());
        CredentialsListResponse credentialsListResponse = new CredentialsListResponse();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();
        String user_hash = claims.get("sub").toString();
        System.out.println("User Hash: "+user_hash);

        if(user_hash == null)
            return new CredentialsListResponse();

        try {
            // onlyValid requested && onlyValid supported by the QTSP
            boolean onlyValid = listRequestDTO.getOnlyValid() && credentialsConfig.getOnlyValidSupport();
            credentialsListResponse.setOnlyValid(onlyValid);

            // get the list of the available credentials of the user
            List<String> listAvailableCredentialsId = credentialsService.getAvailableCredentialsID(user_hash, onlyValid);
            credentialsListResponse.setCredentialIDs(listAvailableCredentialsId);

            if(listRequestDTO.getCredentialInfo()){ // return the main information included in the public key certificate and the public key certificate or the certificate chain
                List<CredentialsListResponse.CredentialInfo> ci =
                      credentialsService.getCredentialInfo(
                            listAvailableCredentialsId,
                            listRequestDTO.getCertificates(),
                            listRequestDTO.getCertInfo(),
                            listRequestDTO.getAuthInfo());
                credentialsListResponse.setCredentialInfos(ci);
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return credentialsListResponse;
    }

    @PostMapping(value = "/info", consumes = "application/json", produces = "application/json")
    public CredentialsInfoResponse info(@RequestBody CredentialsInfoRequest infoRequestDTO) {
        System.out.println("start info request");
        System.out.println(infoRequestDTO.toString());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();
        String user_hash = claims.get("sub").toString();
        System.out.println("User Hash: "+user_hash);

        CredentialsInfoResponse credentialsInfoResponse = new CredentialsInfoResponse();
        if(!credentialsService.credentialBelongsToUser(user_hash, infoRequestDTO.getCredentialID())){
            return credentialsInfoResponse;
        }

        try {
            credentialsInfoResponse = credentialsService.getCredentialInfoFromSingleCredential(
                  infoRequestDTO.getCredentialID(),
                  infoRequestDTO.getCertificates(),
                  infoRequestDTO.getCertInfo(),
                  infoRequestDTO.getAuthInfo());
        }catch (Exception e){
            e.printStackTrace();
        }
        return credentialsInfoResponse;
    }

    // for tests, to be removed
    @GetMapping(value = "/createCredentials")
    public ResponseEntity<?> createCredentials(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();
        String userHash = claims.get("sub").toString();

        try{
            this.credentialsService.createCredential(
                  userHash, this.user_for_tests.getGivenName(), this.user_for_tests.getSurname(),
                  this.user_for_tests.getName(), this.user_for_tests.getIssuingCountry());
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
        catch (Exception e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
