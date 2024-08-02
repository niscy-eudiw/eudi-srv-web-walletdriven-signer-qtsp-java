package eu.europa.ec.eudi.signer.r3.web;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Enumeration;


@RestController
public class DefaultController {

	@GetMapping("/")
	public void root() throws Exception {
		System.out.println("first call");

		try(CloseableHttpClient httpClient = HttpClients.createDefault() ) {
			HttpGet request = new HttpGet(
				"http://localhost:9000/oauth2/authorize?response_type=code&client_id=sca-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fsca-client&scope=service&code_challenge=some_nonce&code_challenge_method=S256&lang=pt-PT&state=12345678"
			);

			// Send Post Request
			HttpResponse response = httpClient.execute(request);

			if(response.getStatusLine().getStatusCode() == 302) {
				HttpEntity entity = response.getEntity();
				if (entity == null) {
					throw new Exception("Presentation Response from Verifier is empty.");
				}
				InputStream inStream = entity.getContent();
				String message = convertStreamToString(inStream);

				System.out.println(response.getStatusLine().getStatusCode());
				System.out.println(message);
			}
		}
	}

	private static String convertStreamToString(InputStream is) throws Exception {
		BufferedReader reader = new BufferedReader(new InputStreamReader(is));
		StringBuilder sb = new StringBuilder();
		String line;
		while ((line = reader.readLine()) != null) {
			sb.append(line).append("\n");
		}
		is.close();
		return sb.toString();
	}

	@GetMapping("/login/oauth2/code/sca-client")
	public void callback(HttpServletRequest request) throws Exception {

		System.out.println(request.getRequestURL());
		System.out.println(request.getQueryString());

		if(request.getParameter("code") != null){
			String code = request.getParameter("code");
			System.out.println(code);
			String state = request.getParameter("state");
			System.out.println(state);

			try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
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
			}
		}
		System.out.println("end second call");
	}
}
