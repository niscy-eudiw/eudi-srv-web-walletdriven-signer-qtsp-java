package eu.europa.ec.eudi.signer.r3.web;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import org.apache.hc.core5.net.URIBuilder;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DefaultController {

	private String generateNonce() throws Exception{
		SecureRandom prng = new SecureRandom();
		String randomNum = String.valueOf(prng.nextInt());
		System.out.println("Code_Verifier: "+ randomNum);
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		byte[] result = sha.digest(randomNum.getBytes());
		String code_challenge = Base64.getUrlEncoder().encodeToString(result);
		System.out.println("Code_Challenge: "+code_challenge);
		return code_challenge;
	}

	@GetMapping("/test/service")
	public void test_service() throws Exception {
		System.out.println("-------------- service test authorize request: ");

		try(CloseableHttpClient httpClient = HttpClientBuilder.create().disableRedirectHandling().build()) {

			String code_challenge = generateNonce();

			URIBuilder uriBuilder = new URIBuilder("http://localhost:9000/oauth2/authorize");
			uriBuilder.setParameter("response_type", "code");
			uriBuilder.setParameter("client_id", "sca-client");
			uriBuilder.setParameter("redirect_uri", "http://localhost:8080/login/oauth2/code/sca-client");
			uriBuilder.setParameter("scope", "service");
			uriBuilder.setParameter("code_challenge", code_challenge);
			uriBuilder.setParameter("code_challenge_method", "S256");
			uriBuilder.setParameter("lang", "pt-PT");
			uriBuilder.setParameter("state", "12345678");
			HttpGet request = new HttpGet(uriBuilder.build());

			HttpResponse response = httpClient.execute(request);
			System.out.println(response.getStatusLine().getStatusCode());

			if(response.getStatusLine().getStatusCode() == 302) {
				String location = response.getLastHeader("Location").getValue();
				System.out.println("Location: " + location);
				String cookie = response.getLastHeader("Set-Cookie").getValue();
				System.out.println("Cookie: " + cookie);
			}
		}
	}

	@GetMapping("/test/credential/first")
	public void test_credential_first() throws Exception {
		System.out.println("-------------- credential test authorize request: ");

		String credentialID = "cred1";
		System.out.println("Testing Credential Authorization for: "+ credentialID);

		try(CloseableHttpClient httpClient = HttpClientBuilder.create().disableRedirectHandling().build()) {

			String code_challenge = generateNonce();

			URIBuilder uriBuilder = new URIBuilder("http://localhost:9000/oauth2/authorize");
			uriBuilder.setParameter("response_type", "code");
			uriBuilder.setParameter("client_id", "sca-client");
			uriBuilder.setParameter("redirect_uri", "http://localhost:8080/login/oauth2/code/sca-client");
			uriBuilder.setParameter("scope", "credential");
			uriBuilder.setParameter("code_challenge", code_challenge);
			uriBuilder.setParameter("code_challenge_method", "S256");
			uriBuilder.setParameter("lang", "pt-PT");
			uriBuilder.setParameter("state", "12345678");

			uriBuilder.setParameter("credentialID", URLEncoder.encode(credentialID, StandardCharsets.UTF_8));
			uriBuilder.setParameter("numSignatures", Integer.toString(1));
			uriBuilder.setParameter("hashes", "some_document_hash");
			uriBuilder.setParameter("hashAlgorithmOID", "2.16.840.1.101.3.4.2.1");

			URI url = uriBuilder.build();
			System.out.println(url);
			HttpGet request = new HttpGet(url);

			HttpResponse response = httpClient.execute(request);
			System.out.println(response.getStatusLine().getStatusCode());

			if(response.getStatusLine().getStatusCode() == 302) {
				String location = response.getLastHeader("Location").getValue();
				System.out.println("Location: " + location);
				String cookie = response.getLastHeader("Set-Cookie").getValue();
				System.out.println("Cookie: " + cookie);
			}
		}
	}

	@GetMapping("/test/credential/second")
	public void test_credential_second() throws Exception {
		System.out.println("-------------- credential test authorize request: ");

		try(CloseableHttpClient httpClient = HttpClientBuilder.create().disableRedirectHandling().build()) {

			String credentialID = "cred1";
			String code_challenge = generateNonce();

			JSONArray documentDigests = new JSONArray();
			JSONObject documentDigest = new JSONObject();
			documentDigest.put("hash", "some_document_hash");
			documentDigest.put("label", "This is some document hash");
			documentDigests.put(documentDigest);

			JSONObject authorization_details = new JSONObject();
			authorization_details.put("type", "credential");
			authorization_details.put("credentialID", URLEncoder.encode(credentialID, StandardCharsets.UTF_8));
			authorization_details.put("documentDigests", documentDigests);
			authorization_details.put("hashAlgorithmOID", "2.16.840.1.101.3.4.2.1");
			System.out.println(authorization_details);

			URIBuilder uriBuilder = new URIBuilder("http://localhost:9000/oauth2/authorize");
			uriBuilder.setParameter("response_type", "code");
			uriBuilder.setParameter("client_id", "sca-client");
			uriBuilder.setParameter("redirect_uri", "http://localhost:8080/login/oauth2/code/sca-client");
			uriBuilder.setParameter("code_challenge", code_challenge);
			uriBuilder.setParameter("code_challenge_method", "S256");
			uriBuilder.setParameter("lang", "pt-PT");
			uriBuilder.setParameter("state", "12345678");
			uriBuilder.setParameter("authorization_details", authorization_details.toString());

			URI url = uriBuilder.build();
			System.out.println(url);
			HttpGet request = new HttpGet(url);

			HttpResponse response = httpClient.execute(request);
			System.out.println(response.getStatusLine().getStatusCode());

			if(response.getStatusLine().getStatusCode() == 302) {
				String location = response.getLastHeader("Location").getValue();
				System.out.println("Location: " + location);
				String cookie = response.getLastHeader("Set-Cookie").getValue();
				System.out.println("Cookie: " + cookie);
			}
		}
	}


	@GetMapping("/after_auth")
	public void after_auth(@RequestBody AuthRequest authRequest) throws Exception {
		System.out.println("------------ second call");

		System.out.println("URL: " + authRequest.getUrl());
		System.out.println("Cookie: " + authRequest.getCookie());

		String location_redirect = null;
		String new_session_id = null;
		try(CloseableHttpClient httpClient = HttpClientBuilder.create().disableRedirectHandling().build()) {
			HttpGet followRequest = new HttpGet(authRequest.getUrl());
			followRequest.setHeader("Cookie", authRequest.getCookie());

			// Send Post Request
			HttpResponse followResponse = httpClient.execute(followRequest);

			System.out.println(followResponse.getStatusLine().getStatusCode());

			for(Header h: followResponse.getAllHeaders()){
				System.out.println(h.getName()+": "+h.getValue());
			}

			if(followResponse.getStatusLine().getStatusCode() == 302) {
				location_redirect = followResponse.getLastHeader("Location").getValue();
				System.out.println(location_redirect);

				new_session_id = followResponse.getLastHeader("Set-Cookie").getElements()[0].toString();
				System.out.println(new_session_id);
			}
		}

		if ( location_redirect==null || new_session_id == null )
			return;

		try(CloseableHttpClient httpClient2 = HttpClientBuilder.create().build()) {
			HttpGet followRequest = new HttpGet(location_redirect);
			followRequest.setHeader("Cookie", new_session_id);

			// Send Post Request
			HttpResponse followResponse = httpClient2.execute(followRequest);

			System.out.println(followResponse.getStatusLine().getStatusCode());

			for(Header h: followResponse.getAllHeaders()){
				System.out.println(h.getName()+": "+h.getValue());
			}

			/*if(followResponse.getStatusLine().getStatusCode() == 302) {

				String location = followResponse.getLastHeader("Location").getValue();
				System.out.println(location);

				HttpEntity entity = followResponse.getEntity();
				if (entity == null) {
					throw new Exception("Presentation Response from Verifier is empty.");
				}
				InputStream inStream = entity.getContent();
				String message = convertStreamToString(inStream);
				System.out.println(message);
			}*/
		}
	}

	@GetMapping("/login/oauth2/code/sca-client")
	public void callback(HttpServletRequest request) throws Exception {

		System.out.println("----------- third call");

		System.out.println(request.getRequestURL());
		System.out.println(request.getQueryString());

		if(request.getParameter("code") != null){
			String code = request.getParameter("code");
			System.out.println("Code: "+code);
			String state = request.getParameter("state");
			System.out.println("State: "+state);

			String url = "http://localhost:9000/oauth2/token?grant_type=authorization_code&code=" + code + "&client_id=sca-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fsca-client";
			System.out.println("Url: "+url);

			/*try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
				String url = "http://localhost:9000/oauth2/token?grant_type=authorization_code&code=" + code + "&client_id=sca-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fsca-client";
				System.out.println(url);

				HttpPost post = new HttpPost(url);
				post.setHeader("Authorization", "Basic c2NhLWNsaWVudDpzZWNyZXQ=");

				// Send Post Request
				HttpResponse response = httpClient.execute(post);

				System.out.println(response.getStatusLine().getStatusCode());

				HttpEntity entity = response.getEntity();
				if (entity == null) {
					throw new Exception("Presentation Response from Verifier is empty.");
				}
				InputStream inStream = entity.getContent();
				String message = convertStreamToString(inStream);

				System.out.println(message);
			}*/
		}
		System.out.println("end second call");
	}
}
