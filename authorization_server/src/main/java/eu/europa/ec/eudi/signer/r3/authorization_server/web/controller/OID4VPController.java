package eu.europa.ec.eudi.signer.r3.authorization_server.web.controller;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import eu.europa.ec.eudi.signer.r3.authorization_server.config.OAuth2IssuerConfig;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.r3.authorization_server.model.oid4vp.variables.SessionUrlRelationList;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oid4vp.OID4VPCrossDeviceAuthenticationEntryPoint;
import eu.europa.ec.eudi.signer.r3.common_tools.utils.WebUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.BufferedImageHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Controller
public class OID4VPController {

	private final Logger logger = LogManager.getLogger(OID4VPController.class);
	private final VerifierClient verifierClient;
	private final OAuth2IssuerConfig issuerConfig;
	private final SessionUrlRelationList sessionUrlRelationList;

	public OID4VPController(@Autowired VerifierClient verifierClient,  @Autowired OAuth2IssuerConfig issuerConfig, @Autowired SessionUrlRelationList sessionUrlRelationList) {
		this.verifierClient = verifierClient;
		this.issuerConfig = issuerConfig;
		this.sessionUrlRelationList = sessionUrlRelationList;
	}

	@GetMapping("/oid4vp/cross-device")
	// @GetMapping(value = "/{barcode}", produces = MediaType.IMAGE_PNG_VALUE)
	public String getOID4VPCrossDevicePage(Model model, @RequestParam String sessionId){
		try {
			String serviceUrl = this.issuerConfig.getUrl();
			String sanitizeCookieString = WebUtils.getSanitizedCookieString(sessionId);
			logger.info("Saved request to JSessionId Cookie {}", sanitizeCookieString);

			String redirectLink = this.verifierClient.initCrossDeviceTransactionToVerifier(sanitizeCookieString, serviceUrl);

			QRCodeWriter barcodeWriter = new QRCodeWriter();
			BitMatrix bitMatrix = barcodeWriter.encode(redirectLink, BarcodeFormat.QR_CODE, 200, 200);

			// BufferedImage image = MatrixToImageWriter.toBufferedImage(bitMatrix);
			// to change the colors of the QR Code
			// MatrixToImageConfig config = new MatrixToImageConfig();
			// MatrixToImageConfig con = new MatrixToImageConfig(0xFF000002 , 0xFFFFC041);
			// BufferedImage image = MatrixToImageWriter.toBufferedImage(bitMatrix, config);

			ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);

			byte[] qrCodeBytes = pngOutputStream.toByteArray();
			String qrCode = Base64.getEncoder().encodeToString(qrCodeBytes);
			model.addAttribute("qrCode", qrCode);

			String urlCrossDeviceCallback = serviceUrl+"/oid4vp/cross-device/callback?session_id="+sessionId;
			model.addAttribute("url", urlCrossDeviceCallback);

			return "cross-device-page";
		}catch (Exception e){
			model.addAttribute("error", "Failed to generate QR Code: " + e.getMessage());
			return "error";
		}
	}

	private String getCookieSessionIdValue(HttpServletRequest request, HttpServletResponse response){
		String cookieSession = null;
		Cookie[] cookies = request.getCookies();

		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if ("JSESSIONID".equals(cookie.getName())) {
					cookieSession = cookie.getValue();
					break;
				}
			}
		}
		if(cookieSession == null) {
			String cookieHeader = response.getHeader("Set-Cookie");
			if (cookieHeader != null) {
				String[] cookiesArray = cookieHeader.split(";");
				for (String c : cookiesArray) {
					if (c.trim().startsWith("JSESSIONID=")) {
						cookieSession = c.trim().substring("JSESSIONID=".length());
						break;
					}
				}
			}
		}
		logger.info("Current Cookie Session: {}", cookieSession);

		return cookieSession;
	}
}
