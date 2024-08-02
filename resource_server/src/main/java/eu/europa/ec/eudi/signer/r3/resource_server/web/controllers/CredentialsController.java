package eu.europa.ec.eudi.signer.r3.resource_server.web.controllers;

import eu.europa.ec.eudi.signer.r3.resource_server.config.CredentialsConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.model.CredentialsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListResponse;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoResponse;

import java.util.List;

@RestController
@RequestMapping(value = "/csc/v2/credentials")
public class CredentialsController {

    private CredentialsService credentialsService;
    private CredentialsConfig credentialsConfig;

    public CredentialsController(@Autowired CredentialsService credentialsService, @Autowired CredentialsConfig credentialsConfig){
        this.credentialsService = credentialsService;
        this.credentialsConfig = credentialsConfig;
    }

    @PostMapping(value = "/list", consumes = "application/json", produces = "application/json")
    public CredentialsListResponse list(@RequestBody CredentialsListRequest listRequestDTO) {
        System.out.println(listRequestDTO.toString());
        CredentialsListResponse credentialsListResponse = new CredentialsListResponse();

        try {
            // onlyValid requested && onlyValid supported by the QTSP
            boolean onlyValid = listRequestDTO.getOnlyValid() && credentialsConfig.getOnlyValidSupport();
            credentialsListResponse.setOnlyValid(onlyValid);

            // get the list of the available credentials of the user
            List<String> listAvailableCredentialsId =
                  credentialsService.getAvailableCredentialsID(
                        listRequestDTO.getUserID(),
                        onlyValid);
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
        System.out.println(infoRequestDTO.toString());
        CredentialsInfoResponse credentialsInfoResponse = new CredentialsInfoResponse();
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
        try{
            this.credentialsService.createCredential();
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
        catch (Exception e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
