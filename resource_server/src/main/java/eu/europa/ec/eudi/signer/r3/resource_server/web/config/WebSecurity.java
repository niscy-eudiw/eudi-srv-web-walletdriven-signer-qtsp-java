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

package eu.europa.ec.eudi.signer.r3.resource_server.web.config;

import eu.europa.ec.eudi.signer.r3.resource_server.config.AuthConfig;
import eu.europa.ec.eudi.signer.r3.resource_server.config.CertificatesProperties;
import eu.europa.ec.eudi.signer.r3.resource_server.config.KeysProperties;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.ejbca.EjbcaService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.issuer.EjbcaCertificateIssuer;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.issuer.ICertificateIssuer;
import eu.europa.ec.eudi.signer.r3.resource_server.model.certificates.issuer.LocalCertificateIssuer;
import eu.europa.ec.eudi.signer.r3.resource_server.model.database.repositories.SecretKeyRepository;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.EncryptionHelper;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.IKeysService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.KeysService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.LocalKeysService;
import eu.europa.ec.eudi.signer.r3.resource_server.model.keys.hsm.HsmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class WebSecurity {

    private static final Logger logger = LoggerFactory.getLogger(WebSecurity.class);

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
              .csrf(AbstractHttpConfigurer::disable)
              .authorizeHttpRequests(authorize ->
                    authorize
                          .requestMatchers("/swagger-ui/**").permitAll()
                          .requestMatchers("/v3/api-docs/**").permitAll()
                          .requestMatchers("/csc/v2/info").permitAll()
                          .requestMatchers("/csc/v2/signatures/signHash").hasAuthority("SCOPE_credential")
                          .requestMatchers("/csc/v2/credentials/info").hasAnyAuthority("SCOPE_credential", "SCOPE_service")
                          .requestMatchers("/csc/v2/credentials/list").hasAuthority("SCOPE_service")
                          .anyRequest().denyAll()
              )
              .oauth2ResourceServer(oauth2ResourceServer ->
                    oauth2ResourceServer.jwt(Customizer.withDefaults())
              );
        return http.build();
    }

    @Bean
    public IKeysService setKeysService(@Autowired KeysProperties keysProperties, @Autowired AuthConfig authProperties, @Autowired SecretKeyRepository configRep) throws Exception {
        logger.info("Use HSM? {}", keysProperties.useHsm());

        EncryptionHelper encryptionHelper = new EncryptionHelper(authProperties);

        if(keysProperties.useHsm()){
            HsmService hsmService = new HsmService();
            IKeysService keysService = new KeysService(hsmService, configRep, encryptionHelper);
            logger.info("Set up Keys Service that uses HSM.");
            return keysService;
        }
        else{
            IKeysService keysService = new LocalKeysService(encryptionHelper, configRep);
            logger.info("Set up Keys Service that doesn't use HSM.");
            return keysService;
        }
    }

    @Bean
    public ICertificateIssuer setCertificateService(@Autowired CertificatesProperties certificatesProperties) throws Exception {
        logger.info("Use EJBCA? {}", certificatesProperties.useEjbca());
        if(certificatesProperties.useEjbca()){
            EjbcaService ejbcaServiceService = new EjbcaService(certificatesProperties.getEjbca());
            ICertificateIssuer certificatesService = new EjbcaCertificateIssuer(ejbcaServiceService);
            logger.info("Set up Certificate Service that uses EJBCA.");
            return certificatesService;
        }
        else {
            ICertificateIssuer certificatesService = new LocalCertificateIssuer(certificatesProperties.getCaSubject());
            logger.info("Set up Certificate Service that doesn't use EJBCA.");
            return certificatesService;
        }
    }

}
