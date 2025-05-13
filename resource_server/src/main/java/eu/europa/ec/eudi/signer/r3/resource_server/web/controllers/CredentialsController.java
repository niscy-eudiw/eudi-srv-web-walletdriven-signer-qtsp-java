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

package eu.europa.ec.eudi.signer.r3.resource_server.web.controllers;

import eu.europa.ec.eudi.signer.r3.common_tools.utils.CryptoUtils;
import eu.europa.ec.eudi.signer.r3.resource_server.config.CredentialsConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListResponse;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfoResponse;
import java.util.List;
import java.util.Map;

import jakarta.validation.Valid;
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
    private final CryptoUtils cryptoUtils;
    private static final Logger logger = LoggerFactory.getLogger(CredentialsController.class);

    public CredentialsController(@Autowired CredentialsService credentialsService, @Autowired CredentialsConfig credentialsConfig) throws Exception {
        this.credentialsService = credentialsService;
        this.credentialsConfig = credentialsConfig;
        this.cryptoUtils = new CryptoUtils();
    }

    /***
     * Endpoint that allows the end user to consult the list of credentials (certificates and key pairs) available to them.
     * @param listRequestDTO the body from the Http Request
     * @return a json response with a list of credentials
     */
    @PostMapping(value = "/list", consumes = "application/json", produces = "application/json")
    public CredentialsListResponse list(@RequestBody CredentialsListRequest listRequestDTO) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();
        if(logger.isTraceEnabled()) auxDebugLogs(claims);

        String userHash = claims.get("sub").toString();
        logger.trace("Request received at /csc/v2/credentials/list with the body {} from the user {}",
              listRequestDTO.toString(), userHash);

        if(userHash == null) userMissingError();

        if(!claims.containsKey("givenName")|| !claims.containsKey("surname") || !claims.containsKey("issuingCountry")){
            logger.error("Missing required claims from Authentication Header.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing required claims from Authentication Header.");
        }

        String givenName = claims.get("givenName").toString();
        logger.trace("givenName: {}", givenName);
        String surname = claims.get("surname").toString();
        logger.trace("surname: {}", surname);
        String issuingCountry = claims.get("issuingCountry").toString();
        logger.trace("issuingCountry: {}", issuingCountry);

        try {
            CredentialsListResponse credentialsListResponse = new CredentialsListResponse();

            // onlyValid requested && onlyValid supported by the QTSP
            boolean onlyValid = listRequestDTO.getOnlyValid() && credentialsConfig.getOnlyValidSupport();
            credentialsListResponse.setOnlyValid(onlyValid);
            logger.info("OnlyValid value = {}", onlyValid);

            // get the list of the available credentials of the user
            List<String> listAvailableCredentialsId = credentialsService.getAvailableCredentialsID(userHash, onlyValid);
            if(listAvailableCredentialsId.isEmpty() || !this.credentialsService.existsActiveCertificate(listAvailableCredentialsId)){
                logger.info("There are no active certificates.");
                String givenNameDecrypted = this.cryptoUtils.decryptString(givenName);
                String surnameDecrypted = this.cryptoUtils.decryptString(surname);
              
                logger.info("Creating Credential for User {} {}", givenNameDecrypted, surnameDecrypted);

                this.credentialsService.createECDSAP256Credential(userHash, givenNameDecrypted, surnameDecrypted, givenNameDecrypted+" "+surnameDecrypted, issuingCountry);
                logger.info("Issued new Credential.");
                listAvailableCredentialsId = credentialsService.getAvailableCredentialsID(userHash, onlyValid);
                logger.info("Retrieved list of available Credentials.");
            }
            credentialsListResponse.setCredentialIDs(listAvailableCredentialsId);
            logger.info("Added the list of available credentials ID to the response.");

            if(listRequestDTO.getCredentialInfo()){
                // return the main information included in the public key certificate
                // and the public key certificate or the certificate chain
                List<CredentialsListResponse.CredentialInfo> ci = credentialsService.getCredentialInfo(
                      listAvailableCredentialsId, listRequestDTO.getCertificates(),
                      listRequestDTO.getCertInfo(), listRequestDTO.getAuthInfo());
                credentialsListResponse.setCredentialInfos(ci);
                logger.info("Added the credentials info to the response.");
            }
            return credentialsListResponse;
        }
        catch (Exception e){
            e.printStackTrace();
            logger.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request");
        }
    }

    private void auxDebugLogs(Map<String, Object> claims){
        StringBuilder stringBuilder = new StringBuilder();
        for(Map.Entry<String, Object> c: claims.entrySet()){
            stringBuilder.append(c.getKey()).append(": ").append(c.getValue()).append("/n");
        }
        logger.trace("Access Token Claims: {}", stringBuilder);
    }

    private void userMissingError() throws ResponseStatusException{
        logger.error("invalid_request: Invalid user sub in the Authorization Header.");
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request: Invalid or missing user identifier.");
    }

    /**
     * Endpoint that allows the end user to obtain information about a credential (certificate and key pair) available to them.
     * @param infoRequestDTO the body of the Http Request
     * @return a json response containing information about the credential
     */
    @PostMapping(value = "/info", consumes = "application/json", produces = "application/json")
    public CredentialsInfoResponse info(@Valid @RequestBody CredentialsInfoRequest infoRequestDTO) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Map<String, Object> claims = ((Jwt) principal).getClaims();
        if(logger.isTraceEnabled()) auxDebugLogs(claims);

        String userHash = claims.get("sub").toString();
        logger.trace("Request received at /csc/v2/credentials/info with the body {} from the user {}",
              infoRequestDTO.toString(), userHash);

        if(userHash == null) userMissingError();

        if(!credentialsService.credentialBelongsToUser(userHash, infoRequestDTO.getCredentialID())){
            logger.error("Invalid Request: CredentialID doesn't belong to the {}", userHash);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request: Invalid parameter credentialID.");
        }

        try {
            CredentialsInfoResponse credentialsInfoResponse = credentialsService.getCredentialInfoFromSingleCredential(
                  infoRequestDTO.getCredentialID(), infoRequestDTO.getCertificates(), infoRequestDTO.getCertInfo(),
                  infoRequestDTO.getAuthInfo());
            logger.info("Obtained CredentialsInfo of the CredentialId {}", infoRequestDTO.getCredentialID());
            return credentialsInfoResponse;
        }
        catch (Exception e){
            logger.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_request");
        }
    }
}
