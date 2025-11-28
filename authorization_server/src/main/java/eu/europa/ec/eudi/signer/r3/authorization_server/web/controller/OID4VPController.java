package eu.europa.ec.eudi.signer.r3.authorization_server.web.controller;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.ServiceURLConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.OpenIdForVPService;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token.CommonTokenSetting;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.util.Base64;
import java.util.Map;

@Controller
public class OID4VPController {
	private final Logger logger = LoggerFactory.getLogger(OID4VPController.class);
	private final OpenIdForVPService openIdForVPService;
	private final ServiceURLConfig issuerConfig;
	private final SessionUrlRelationList sessionUrlRelationList;
	private final CommonTokenSetting tokenSetting;

	public OID4VPController(@Autowired OpenIdForVPService openIdForVPService, @Autowired ServiceURLConfig issuerConfig, @Autowired SessionUrlRelationList sessionUrlRelationList, @Autowired CommonTokenSetting tokenSetting) {
		this.openIdForVPService = openIdForVPService;
		this.issuerConfig = issuerConfig;
		this.sessionUrlRelationList = sessionUrlRelationList;
		this.tokenSetting = tokenSetting;
	}

	@GetMapping("/oid4vp/cross-device")
	public String getOID4VPCrossDevicePage(Model model, @RequestParam String sessionId){
		try {
			String serviceUrl = this.issuerConfig.getServiceURL();
			String sanitizeCookie = WebUtils.getSanitizedCookieString(sessionId);
			logger.info("Retrieved saved request to JSessionId Cookie {}", sanitizeCookie);

			String urlToReturnTo = this.sessionUrlRelationList.getSessionInformation(sanitizeCookie).getUrlToReturnTo();

			//System.out.println("URL REQUEST: "+urlToReturnTo);
			//logger.info("URL REQUEST: {}", urlToReturnTo);

			//JSONArray transaction_data = getTransactionData(urlToReturnTo);
			//System.out.println("TRANSACTION_DATA_CONTROLLER: "+ transaction_data);
			//logger.info("TRANSACTION_DATA_CONTROLLER: {}", transaction_data);

			//String redirectLink = this.verifierClient.initCrossDeviceTransactionToVerifier(sanitizeCookie, serviceUrl, transaction_data);
			//logger.info("Retrieved the redirect link for cross device authentication.");

			String redirectLink = this.openIdForVPService.getCrossDeviceRedirectLink(urlToReturnTo, sanitizeCookie, serviceUrl);

			QRCodeWriter barcodeWriter = new QRCodeWriter();
			BitMatrix bitMatrix = barcodeWriter.encode(redirectLink, BarcodeFormat.QR_CODE, 200, 200);
			ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
			byte[] qrCodeBytes = pngOutputStream.toByteArray();
			String qrCode = Base64.getEncoder().encodeToString(qrCodeBytes);
			model.addAttribute("qrCode", qrCode);
			logger.info("Generated QrCode for cross-device flow.");

			String urlCrossDeviceCallback = serviceUrl+"/oid4vp/cross-device/callback?session_id="+sessionId;
			model.addAttribute("url", urlCrossDeviceCallback);
			logger.info("Define the Callback Url.");

			URI url = new URI(urlToReturnTo);
			Map<String, String> queryValues = this.tokenSetting.getQueryValues(url);
			String scope = this.tokenSetting.getScopeFromOAuth2Request(queryValues);

			if(scope.equals("credential")) {
				model.addAttribute("reason", "use your keys to sign your document.");
				model.addAttribute("resources", "the chosen signing key to sign your document.");
			}
			else if (scope.equals("service")){
				model.addAttribute("reason", "your account.");
				model.addAttribute("resources", "your list of certificates and, " +
					  "if no certificate exists, you will grant access to issue a new certificate and a new key pair");
			}

			return "cross-device-page";
		}catch (Exception e){
			logger.error(e.getLocalizedMessage());
			logger.error(e.getMessage());
			model.addAttribute("errormessage", "Failed to generate QR Code: " + e.getMessage());
			return "error";
		}
	}
}
