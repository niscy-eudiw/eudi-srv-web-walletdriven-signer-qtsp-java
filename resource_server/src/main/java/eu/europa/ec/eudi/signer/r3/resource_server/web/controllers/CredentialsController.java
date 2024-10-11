package eu.europa.ec.eudi.signer.r3.resource_server.web.controllers;

import eu.europa.ec.eudi.signer.r3.resource_server.config.CredentialsConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListResponse;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoResponse;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(value = "/csc/v2/credentials")
public class CredentialsController {

    private final CredentialsService credentialsService;
    private final CredentialsConfig credentialsConfig;
    private static final Logger logger = LoggerFactory.getLogger(CredentialsController.class);

    public CredentialsController(@Autowired CredentialsService credentialsService, @Autowired CredentialsConfig credentialsConfig) throws Exception{
        this.credentialsService = credentialsService;
        this.credentialsConfig = credentialsConfig;
    }

    @PostMapping(value = "/list", consumes = "application/json", produces = "application/json")
    public CredentialsListResponse list(@RequestBody CredentialsListRequest listRequestDTO) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();

        StringBuilder stringBuilder = new StringBuilder();
        for(Map.Entry<String, Object> c: claims.entrySet()){
            stringBuilder.append(c.getKey()).append(": ").append(c.getValue()).append("/n");
        }
        logger.trace("Access Token Claims: {}", stringBuilder.toString());

        String userHash = claims.get("sub").toString();
        String givenName = claims.get("givenName").toString();
        String surname = claims.get("surname").toString();
        String issuingCountry = claims.get("issuingCountry").toString();

        logger.info("Request received at /csc/v2/credentials/list with the body {} from the user {}", listRequestDTO.toString(), userHash );

        if(userHash == null){
            logger.error("Invalid Request: Invalid user sub in the Authorization Header.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request: Invalid user sub.");
        }

        try {
            CredentialsListResponse credentialsListResponse = new CredentialsListResponse();

            // onlyValid requested && onlyValid supported by the QTSP
            boolean onlyValid = listRequestDTO.getOnlyValid() && credentialsConfig.getOnlyValidSupport();
            credentialsListResponse.setOnlyValid(onlyValid);
            logger.info("OnlyValid value = {}", onlyValid);

            // get the list of the available credentials of the user
            List<String> listAvailableCredentialsId = credentialsService.getAvailableCredentialsID(userHash, onlyValid);
            if(listAvailableCredentialsId.isEmpty()){
                logger.info("Empty List of Available Credentials.");
                this.credentialsService.createRSACredential(userHash, givenName, surname, givenName+" "+surname, issuingCountry);
                listAvailableCredentialsId = credentialsService.getAvailableCredentialsID(userHash, onlyValid);
            }
            credentialsListResponse.setCredentialIDs(listAvailableCredentialsId);
            logger.info("Added the Available Credentials ID to the response.");

            if(listRequestDTO.getCredentialInfo()){ // return the main information included in the public key certificate and the public key certificate or the certificate chain
                List<CredentialsListResponse.CredentialInfo> ci
                      = credentialsService.getCredentialInfo(listAvailableCredentialsId, listRequestDTO.getCertificates(), listRequestDTO.getCertInfo(), listRequestDTO.getAuthInfo());
                credentialsListResponse.setCredentialInfos(ci);
                logger.info("Added the Credentials Info to the response.");
            }
            return credentialsListResponse;
        }
        catch (Exception e){
            e.printStackTrace();
            logger.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request");
        }
    }

    @PostMapping(value = "/info", consumes = "application/json", produces = "application/json")
    public CredentialsInfoResponse info(@RequestBody CredentialsInfoRequest infoRequestDTO) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(authentication.getClass());

        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();

        StringBuilder stringBuilder = new StringBuilder();
        for(Map.Entry<String, Object> c: claims.entrySet()){
            stringBuilder.append(c.getKey()).append(": ").append(c.getValue()).append("/n");
        }
        logger.trace("Access Token Claims: {}", stringBuilder.toString());

        String userHash = claims.get("sub").toString();
        logger.info("Request received at /csc/v2/credentials/list with the body {} from the user {}", infoRequestDTO.toString(), userHash);

        if(!credentialsService.credentialBelongsToUser(userHash, infoRequestDTO.getCredentialID())){
            logger.error("Invalid Request: CredentialID doesn't belong to the {}", userHash);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request: Invalid parameter credentialID.");
        }

        try {
            CredentialsInfoResponse credentialsInfoResponse = credentialsService.getCredentialInfoFromSingleCredential(infoRequestDTO.getCredentialID(), infoRequestDTO.getCertificates(), infoRequestDTO.getCertInfo(), infoRequestDTO.getAuthInfo());
            logger.info("Obtained CredentialsInfo of the CredentialId {}", infoRequestDTO.getCredentialID());
            return credentialsInfoResponse;
        }
        catch (Exception e){
            logger.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request");
        }
    }
}
