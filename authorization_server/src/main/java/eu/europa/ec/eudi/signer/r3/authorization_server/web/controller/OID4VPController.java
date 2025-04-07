package eu.europa.ec.eudi.signer.r3.authorization_server.web.controller;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.OAuth2IssuerConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token.CommonTokenSetting;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

	private final Logger logger = LogManager.getLogger(OID4VPController.class);
	private final VerifierClient verifierClient;
	private final OAuth2IssuerConfig issuerConfig;
	private final SessionUrlRelationList sessionUrlRelationList;
	private final CommonTokenSetting tokenSetting;

	public OID4VPController(@Autowired VerifierClient verifierClient,  @Autowired OAuth2IssuerConfig issuerConfig, @Autowired SessionUrlRelationList sessionUrlRelationList, @Autowired CommonTokenSetting tokenSetting) {
		this.verifierClient = verifierClient;
		this.issuerConfig = issuerConfig;
		this.sessionUrlRelationList = sessionUrlRelationList;
		this.tokenSetting = tokenSetting;
	}

	@GetMapping("/oid4vp/cross-device")
	public String getOID4VPCrossDevicePage(Model model, @RequestParam String sessionId){
		try {
			String serviceUrl = this.issuerConfig.getUrl();
			String sanitizeCookieString = WebUtils.getSanitizedCookieString(sessionId);
			logger.info("Retrieved saved request to JSessionId Cookie {}", sanitizeCookieString);

			String redirectLink = this.verifierClient.initCrossDeviceTransactionToVerifier(sanitizeCookieString, serviceUrl);
			logger.info("Retrieved the redirectLink.");

			QRCodeWriter barcodeWriter = new QRCodeWriter();
			BitMatrix bitMatrix = barcodeWriter.encode(redirectLink, BarcodeFormat.QR_CODE, 200, 200);

			ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);

			byte[] qrCodeBytes = pngOutputStream.toByteArray();
			String qrCode = Base64.getEncoder().encodeToString(qrCodeBytes);
			model.addAttribute("qrCode", qrCode);

			String urlCrossDeviceCallback = serviceUrl+"/oid4vp/cross-device/callback?session_id="+sessionId;
			model.addAttribute("url", urlCrossDeviceCallback);

			String urlToReturnTo = this.sessionUrlRelationList.getSessionInformation(sanitizeCookieString).getUrlToReturnTo();
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
