package eu.europa.ec.eudi.signer.r3.resource_server.web.controllers;

import eu.europa.ec.eudi.signer.r3.resource_server.config.InfoConfig;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.InfoResponse;

@RestController
@RequestMapping(value = "/csc/v2/info")
public class InfoController {
    private final InfoConfig infoProperties;
    private final Logger log = LoggerFactory.getLogger(InfoController.class);

    public InfoController(@Autowired InfoConfig infoProperties){
        this.infoProperties = infoProperties;
    }

    @PostMapping(consumes = "application/json", produces = "application/json")
    public InfoResponse info(@RequestBody Map<String, Object> requestMessage) {
        log.trace("Receive request ");
        System.out.println(requestMessage);
        System.out.println(infoProperties.toString());

        List<String> keySet = this.infoProperties.getSignature_formats().keySet().stream().toList();;

        List<List<String>> envelope_properties = new ArrayList<>();
        for (String o : keySet) {
            System.out.println(o);
            List<String> env_properties = this.infoProperties.getSignature_formats().get(o);
            envelope_properties.add(env_properties);
        }

        return new InfoResponse(
             this.infoProperties.getSpecs(), this.infoProperties.getName(), this.infoProperties.getLogo(),
             this.infoProperties.getRegion(), this.infoProperties.getLang(), this.infoProperties.getDescription(),
             this.infoProperties.getAuthType(), this.infoProperties.getOauth2(), this.infoProperties.getAsynchronousOperationMode(),
             this.infoProperties.getMethods(), this.infoProperties.getValidationInfo(), this.infoProperties.getSignAlgorithms(),
             keySet, envelope_properties, this.infoProperties.getConformance_levels());
    }

}
