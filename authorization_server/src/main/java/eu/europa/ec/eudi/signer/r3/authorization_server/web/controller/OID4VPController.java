package eu.europa.ec.eudi.signer.r3.authorization_server.web.controller;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.util.Base64;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import eu.europa.ec.eudi.signer.r3.authorization_server.config.ServiceURLConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2ScopesNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.token.CommonTokenSetting;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;

@Controller
public class OID4VPController {
	private static final String ERROR_VIEW = "error";
	private static final String ERROR_MESSAGE_ATTRIBUTE = "errormessage";
	private static final String NO_ACTIVE_SESSION_MESSAGE = "No active authentication session found.";

	private final Logger logger = LoggerFactory.getLogger(OID4VPController.class);
	private final ServiceURLConfig issuerConfig;
	private final SessionUrlRelationList sessionUrlRelationList;
	private final CommonTokenSetting tokenSetting;

	public OID4VPController(@Autowired ServiceURLConfig issuerConfig, @Autowired SessionUrlRelationList sessionUrlRelationList, @Autowired CommonTokenSetting tokenSetting) {
		this.issuerConfig = issuerConfig;
		this.sessionUrlRelationList = sessionUrlRelationList;
		this.tokenSetting = tokenSetting;
	}

	@GetMapping("/oid4vp/cross-device")
	public String getOID4VPCrossDevicePage(Model model, @CookieValue(name = "JSESSIONID", required = false) String sessionId){
		if (sessionId == null) {
			logger.error("No session cookie present in the cross-device request.");
			model.addAttribute(ERROR_MESSAGE_ATTRIBUTE, NO_ACTIVE_SESSION_MESSAGE);
			return ERROR_VIEW;
		}

		String sanitizeCookie = WebUtils.getSanitizedCookieString(sessionId);
		SessionUrlRelationList.SessionUrlRelation sessionInformation = this.sessionUrlRelationList.getSessionInformation(sanitizeCookie);
		if (sessionInformation == null || sessionInformation.getWalletLink() == null) {
			logger.error("No Wallet link found for session {}", sanitizeCookie);
			model.addAttribute(ERROR_MESSAGE_ATTRIBUTE, NO_ACTIVE_SESSION_MESSAGE);
			return ERROR_VIEW;
		}

		try {
			String serviceUrl = this.issuerConfig.getServiceURL();
			String urlToReturnTo = sessionInformation.getUrlToReturnTo();
			String redirectLink = sessionInformation.getWalletLink();

			QRCodeWriter barcodeWriter = new QRCodeWriter();
			BitMatrix bitMatrix = barcodeWriter.encode(redirectLink, BarcodeFormat.QR_CODE, 200, 200);
			ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
			byte[] qrCodeBytes = pngOutputStream.toByteArray();
			String qrCode = Base64.getEncoder().encodeToString(qrCodeBytes);
			model.addAttribute("qrCode", qrCode);
			logger.info("Generated QrCode for cross-device flow.");

			String urlCrossDeviceCallback = serviceUrl+"/oid4vp/cross-device/callback?session_id="+sanitizeCookie;
			model.addAttribute("url", urlCrossDeviceCallback);
			logger.info("Define the Callback Url.");

			URI url = new URI(urlToReturnTo);
			Map<String, String> queryValues = this.tokenSetting.getQueryValues(url);
			String scope = this.tokenSetting.getScopeFromOAuth2Request(queryValues);

			if(scope.equals(OAuth2ScopesNames.CREDENTIAL)) {
				model.addAttribute("reason", "use your keys to sign your document.");
				model.addAttribute("resources", "the chosen signing key to sign your document.");
			}
			else if (scope.equals(OAuth2ScopesNames.SERVICE)){
				model.addAttribute("reason", "your account.");
				model.addAttribute("resources", "your list of certificates and, " +
					  "if no certificate exists, you will grant access to issue a new certificate and a new key pair");
			}
			else if (scope.equals(OAuth2ScopesNames.CREDENTIAL_CREATION)){
				model.addAttribute("reason", "create a new certificate.");
				model.addAttribute("resources", "create a new certificate and signing key pair.");
			}
			else if(scope.equals(OAuth2ScopesNames.CREDENTIAL_DELETION)){
				model.addAttribute("reason", "delete a certificate.");
				model.addAttribute("resources", "delete a certificate from your list of certificates.");
			}
			return "cross-device-page";
		}catch (Exception e){
			logger.error(e.getLocalizedMessage());
			logger.error(e.getMessage());
			model.addAttribute(ERROR_MESSAGE_ATTRIBUTE, "Failed to generate QR Code: " + e.getMessage());
			return ERROR_VIEW;
		}
	}


	@GetMapping("/oid4vp/same-device")
	public String getOID4VPSameDevicePage(Model model, @CookieValue(name = "JSESSIONID", required = false) String sessionId){
		if (sessionId == null) {
			logger.error("No session cookie present in the same-device request.");
			model.addAttribute(ERROR_MESSAGE_ATTRIBUTE, NO_ACTIVE_SESSION_MESSAGE);
			return ERROR_VIEW;
		}

		String sanitizeCookie = WebUtils.getSanitizedCookieString(sessionId);
		SessionUrlRelationList.SessionUrlRelation sessionInformation = this.sessionUrlRelationList.getSessionInformation(sanitizeCookie);
		if (sessionInformation == null || sessionInformation.getWalletLink() == null) {
			logger.error("No Wallet link found for session {}", sanitizeCookie);
			model.addAttribute(ERROR_MESSAGE_ATTRIBUTE, NO_ACTIVE_SESSION_MESSAGE);
			return ERROR_VIEW;
		}

		model.addAttribute("url", sessionInformation.getWalletLink());
		return "same-device-page";
	}
}
