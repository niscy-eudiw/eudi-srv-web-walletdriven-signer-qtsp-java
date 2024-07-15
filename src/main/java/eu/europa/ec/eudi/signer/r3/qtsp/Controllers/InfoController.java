package eu.europa.ec.eudi.signer.r3.qtsp.Controllers;

import java.util.Map;

import eu.europa.ec.eudi.signer.r3.qtsp.config.InfoProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.r3.qtsp.DTO.InfoResponse;

@RestController
@RequestMapping(value = "/csc/v2/info")
public class InfoController {

    @Autowired
    private InfoProperties infoProperties;

    @PostMapping(consumes = "application/json", produces = "application/json")
    public InfoResponse info(@RequestBody Map<String, Object> requestMessage) {
        System.out.println(requestMessage);
        if (requestMessage.containsKey("lang")) {
            try {
                Object language = requestMessage.get("lang");
                String lang = (String) language;
                System.out.println(lang);
                return new InfoResponse();
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

}
